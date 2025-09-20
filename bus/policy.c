/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* policy.c  Bus security policy
 *
 * Copyright (C) 2003, 2004  Red Hat, Inc.
 *
 * SPDX-License-Identifier: AFL-2.1 OR GPL-2.0-or-later
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <config.h>
#include "policy.h"
#include "services.h"
#include "test.h"
#include "utils.h"
#include <dbus/dbus-list.h>
#include <dbus/dbus-hash.h>
#include <dbus/dbus-internals.h>
#include <dbus/dbus-message-internal.h>
#include <dbus/dbus-connection-internal.h>

struct BusClientPolicy
{
  int refcount;

  BusPolicy *policy;
  unsigned long *groups;
  int n_groups;
  dbus_uid_t uid;
  dbus_bool_t uid_set;
  dbus_bool_t at_console;
};

BusPolicyRule*
bus_policy_rule_new (BusPolicyRuleType type,
                     dbus_bool_t       allow)
{
  BusPolicyRule *rule;

  rule = dbus_new0 (BusPolicyRule, 1);
  if (rule == NULL)
    return NULL;

  rule->type = type;
  rule->refcount = 1;
  rule->allow = allow;

  switch (rule->type)
    {
    case BUS_POLICY_RULE_USER:
      rule->d.user.uid = DBUS_UID_UNSET;
      break;
    case BUS_POLICY_RULE_GROUP:
      rule->d.group.gid = DBUS_GID_UNSET;
      break;
    case BUS_POLICY_RULE_SEND:
      rule->d.send.message_type = DBUS_MESSAGE_TYPE_INVALID;

      /* allow rules default to TRUE (only requested replies allowed)
       * deny rules default to FALSE (only unrequested replies denied)
       */
      rule->d.send.requested_reply = rule->allow;
      break;
    case BUS_POLICY_RULE_RECEIVE:
      rule->d.receive.message_type = DBUS_MESSAGE_TYPE_INVALID;
      /* allow rules default to TRUE (only requested replies allowed)
       * deny rules default to FALSE (only unrequested replies denied)
       */
      rule->d.receive.requested_reply = rule->allow;
      break;
    case BUS_POLICY_RULE_OWN:
      break;
    default:
      _dbus_assert_not_reached ("invalid rule");
    }
  
  return rule;
}

BusPolicyRule *
bus_policy_rule_ref (BusPolicyRule *rule)
{
  _dbus_assert (rule->refcount > 0);

  rule->refcount += 1;

  return rule;
}

void
bus_policy_rule_unref (BusPolicyRule *rule)
{
  _dbus_assert (rule->refcount > 0);

  rule->refcount -= 1;
  
  if (rule->refcount == 0)
    {
      switch (rule->type)
        {
        case BUS_POLICY_RULE_SEND:
          dbus_free (rule->d.send.path);
          dbus_free (rule->d.send.interface);
          dbus_free (rule->d.send.member);
          dbus_free (rule->d.send.error);
          dbus_free (rule->d.send.destination);
          break;
        case BUS_POLICY_RULE_RECEIVE:
          dbus_free (rule->d.receive.path);
          dbus_free (rule->d.receive.interface);
          dbus_free (rule->d.receive.member);
          dbus_free (rule->d.receive.error);
          dbus_free (rule->d.receive.origin);
          break;
        case BUS_POLICY_RULE_OWN:
          dbus_free (rule->d.own.service_name);
          break;
        case BUS_POLICY_RULE_USER:
          break;
        case BUS_POLICY_RULE_GROUP:
          break;
        default:
          _dbus_assert_not_reached ("invalid rule");
        }
      
      dbus_free (rule);
    }
}

struct BusPolicy
{
  int refcount;

  DBusList *default_rules;         /**< Default policy rules */
  DBusList *mandatory_rules;       /**< Mandatory policy rules */
  DBusHashTable *rules_by_uid;     /**< per-UID policy rules */
  DBusHashTable *rules_by_gid;     /**< per-GID policy rules */
  DBusList *at_console_true_rules; /**< console user policy rules where at_console="true"*/
  DBusList *at_console_false_rules; /**< console user policy rules where at_console="false"*/

  DBusHashTable *default_rules_by_name;
  DBusList *default_prefix_rules;
  unsigned int n_default_rules;
};

typedef struct BusPolicyRulesWithScore
{
  DBusList *rules;
  int score;
} BusPolicyRulesWithScore;

static void
free_rule_func (void *data,
                void *user_data)
{
  BusPolicyRule *rule = data;

  bus_policy_rule_unref (rule);
}

static void
free_rule_list_func (void *data)
{
  DBusList **list = data;

  if (list == NULL) /* DBusHashTable is on crack */
    return;
  
  _dbus_list_foreach (list, free_rule_func, NULL);
  
  _dbus_list_clear (list);

  dbus_free (list);
}

static void
free_rule_list_with_score_func (void *data)
{
  BusPolicyRulesWithScore *rules = data;

  if (rules == NULL)
    return;

  _dbus_list_foreach (&rules->rules, free_rule_func, NULL);

  _dbus_list_clear (&rules->rules);

  dbus_free (rules);
}

BusPolicy*
bus_policy_new (void)
{
  BusPolicy *policy;

  policy = dbus_new0 (BusPolicy, 1);
  if (policy == NULL)
    return NULL;

  policy->refcount = 1;
  
  policy->rules_by_uid = _dbus_hash_table_new (DBUS_HASH_UINTPTR,
                                               NULL,
                                               free_rule_list_func);
  if (policy->rules_by_uid == NULL)
    goto failed;

  policy->rules_by_gid = _dbus_hash_table_new (DBUS_HASH_UINTPTR,
                                               NULL,
                                               free_rule_list_func);
  if (policy->rules_by_gid == NULL)
    goto failed;

  policy->default_rules_by_name = _dbus_hash_table_new (DBUS_HASH_STRING,
                                                        NULL,
                                                        free_rule_list_with_score_func);
  if (policy->default_rules_by_name == NULL)
    goto failed;

  return policy;
  
 failed:
  bus_policy_unref (policy);
  return NULL;
}

BusPolicy *
bus_policy_ref (BusPolicy *policy)
{
  _dbus_assert (policy->refcount > 0);

  policy->refcount += 1;

  return policy;
}

void
bus_policy_unref (BusPolicy *policy)
{
  _dbus_assert (policy->refcount > 0);

  policy->refcount -= 1;

  if (policy->refcount == 0)
    {
      _dbus_list_foreach (&policy->default_rules, free_rule_func, NULL);
      _dbus_list_clear (&policy->default_rules);

      _dbus_list_foreach (&policy->mandatory_rules, free_rule_func, NULL);
      _dbus_list_clear (&policy->mandatory_rules);

      _dbus_list_foreach (&policy->at_console_true_rules, free_rule_func, NULL);
      _dbus_list_clear (&policy->at_console_true_rules);

      _dbus_list_foreach (&policy->at_console_false_rules, free_rule_func, NULL);
      _dbus_list_clear (&policy->at_console_false_rules);

      if (policy->rules_by_uid)
        {
          _dbus_hash_table_unref (policy->rules_by_uid);
          policy->rules_by_uid = NULL;
        }

      if (policy->rules_by_gid)
        {
          _dbus_hash_table_unref (policy->rules_by_gid);
          policy->rules_by_gid = NULL;
        }

      if (policy->default_rules_by_name)
        {
          _dbus_hash_table_unref (policy->default_rules_by_name);
          policy->default_rules_by_name = NULL;
        }

      _dbus_list_foreach (&policy->default_prefix_rules, free_rule_func, NULL);
      _dbus_list_clear (&policy->default_prefix_rules);

      dbus_free (policy);
    }
}

BusClientPolicy*
bus_policy_create_client_policy (BusPolicy      *policy,
                                 DBusConnection *connection,
                                 DBusError      *error)
{
  BusClientPolicy *client;

  _dbus_assert (dbus_connection_get_is_authenticated (connection));
  _DBUS_ASSERT_ERROR_IS_CLEAR (error);
  
  client = bus_client_policy_new ();
  if (client == NULL)
    goto nomem;

  if (_dbus_hash_table_get_n_entries (policy->rules_by_gid) > 0)
    {
      if (!bus_connection_get_unix_groups (connection, &client->groups, &client->n_groups, error))
        goto failed;
    }
  
  if (dbus_connection_get_unix_user (connection, &client->uid))
    {
      client->uid_set = TRUE;
      client->at_console = _dbus_unix_user_is_at_console (client->uid, error);
      
      if (dbus_error_is_set (error) == TRUE)
          goto failed;
    }

  client->policy = bus_policy_ref (policy);

  return client;

 nomem:
  BUS_SET_OOM (error);
 failed:
  _DBUS_ASSERT_ERROR_IS_SET (error);
  if (client)
    bus_client_policy_unref (client);
  return NULL;
}

static dbus_bool_t
list_allows_user (dbus_bool_t           def,
                  DBusList            **list,
                  unsigned long         uid,
                  const unsigned long  *group_ids,
                  int                   n_group_ids)
{
  DBusList *link;
  dbus_bool_t allowed;
  
  allowed = def;

  link = _dbus_list_get_first_link (list);
  while (link != NULL)
    {
      BusPolicyRule *rule = link->data;
      link = _dbus_list_get_next_link (list, link);

      if (rule->type == BUS_POLICY_RULE_USER)
        {
          _dbus_verbose ("List %p user rule uid="DBUS_UID_FORMAT"\n",
                         list, rule->d.user.uid);
          
          if (rule->d.user.uid == DBUS_UID_UNSET)
            ; /* '*' wildcard */
          else if (rule->d.user.uid != uid)
            continue;
        }
      else if (rule->type == BUS_POLICY_RULE_GROUP)
        {
          _dbus_verbose ("List %p group rule gid="DBUS_GID_FORMAT"\n",
                         list, rule->d.group.gid);
          
          if (rule->d.group.gid == DBUS_GID_UNSET)
            ;  /* '*' wildcard */
          else
            {
              int i;
              
              i = 0;
              while (i < n_group_ids)
                {
                  if (rule->d.group.gid == group_ids[i])
                    break;
                  ++i;
                }
              
              if (i == n_group_ids)
                continue;
            }
        }
      else
        continue;

      allowed = rule->allow;
    }
  
  return allowed;
}

dbus_bool_t
bus_policy_allow_unix_user (BusPolicy        *policy,
                            unsigned long     uid)
{
  dbus_bool_t allowed;
  unsigned long *group_ids;
  int n_group_ids;

  /* On OOM or error we always reject the user */
  if (!_dbus_unix_groups_from_uid (uid, &group_ids, &n_group_ids, NULL))
    {
      _dbus_verbose ("Did not get any groups for UID %lu\n",
                     uid);
      return FALSE;
    }

  /* Default to "user owning bus" can connect */
  allowed = _dbus_unix_user_is_process_owner (uid);

  allowed = list_allows_user (allowed,
                              &policy->default_rules,
                              uid,
                              group_ids, n_group_ids);

  allowed = list_allows_user (allowed,
                              &policy->mandatory_rules,
                              uid,
                              group_ids, n_group_ids);

  dbus_free (group_ids);

  _dbus_verbose ("UID %lu allowed = %d\n", uid, allowed);
  
  return allowed;
}

/* For now this is never actually called because the default
 * DBusConnection behavior of 'same user that owns the bus can
 * connect' is all it would do. Set the windows user function in
 * connection.c if the config file ever supports doing something
 * interesting here.
 */
dbus_bool_t
bus_policy_allow_windows_user (BusPolicy        *policy,
                               const char       *windows_sid)
{
  /* Windows has no policies here since only the session bus
   * is really used for now, so just checking that the
   * connecting person is the same as the bus owner is fine.
   */
  return _dbus_windows_user_is_process_owner (windows_sid);
}

static BusPolicyRulesWithScore *
get_rules_by_string (DBusHashTable *hash,
                    const char    *key)
{
  BusPolicyRulesWithScore *rules;

  rules = _dbus_hash_table_lookup_string (hash, key);
  if (rules == NULL)
    {
      rules = dbus_new0 (BusPolicyRulesWithScore, 1);
      if (rules == NULL)
        return NULL;

      if (!_dbus_hash_table_insert_string (hash, (char *)key, rules))
        {
          dbus_free (rules);
          return NULL;
        }
    }

  return rules;
}

static const char *
get_name_from_rule (BusPolicyRule *rule)
{
  const char *name = NULL;
  if (rule->type == BUS_POLICY_RULE_SEND)
    name = rule->d.send.destination;
  else if (rule->type == BUS_POLICY_RULE_RECEIVE)
    name = rule->d.receive.origin;
  else if (rule->type == BUS_POLICY_RULE_OWN)
    name = rule->d.own.service_name;

  if (name == NULL)
    name = "";

  return name;
}

static dbus_bool_t
is_prefix_rule (BusPolicyRule *rule)
{
  if (rule->type == BUS_POLICY_RULE_SEND && rule->d.send.destination_is_prefix)
    return TRUE;
  if (rule->type == BUS_POLICY_RULE_OWN && rule->d.own.prefix)
    return TRUE;

  return FALSE;
}

dbus_bool_t
bus_policy_append_default_rule (BusPolicy      *policy,
                                BusPolicyRule  *rule)
{
  if (rule->type == BUS_POLICY_RULE_USER || rule->type == BUS_POLICY_RULE_GROUP)
    {
      if (!_dbus_list_append (&policy->default_rules, rule))
        return FALSE;
    }
  else
    {
      rule->score = ++policy->n_default_rules;

      if (is_prefix_rule (rule))
        {
          if (!_dbus_list_append (&policy->default_prefix_rules, rule))
            return FALSE;
        }
      else
        {
          DBusList **list;
          BusPolicyRulesWithScore *rules;

          rules = get_rules_by_string (policy->default_rules_by_name,
                                       get_name_from_rule (rule));

          if (rules == NULL)
            return FALSE;

          list = &rules->rules;

          if (!_dbus_list_prepend (list, rule))
            return FALSE;

          rules->score = rule->score;
        }
    }

  bus_policy_rule_ref (rule);

  return TRUE;
}

dbus_bool_t
bus_policy_append_mandatory_rule (BusPolicy      *policy,
                                  BusPolicyRule  *rule)
{
  if (!_dbus_list_append (&policy->mandatory_rules, rule))
    return FALSE;

  bus_policy_rule_ref (rule);

  return TRUE;
}



static DBusList**
get_list (DBusHashTable *hash,
          unsigned long  key)
{
  DBusList **list;

  list = _dbus_hash_table_lookup_uintptr (hash, key);

  if (list == NULL)
    {
      list = dbus_new0 (DBusList*, 1);
      if (list == NULL)
        return NULL;

      if (!_dbus_hash_table_insert_uintptr (hash, key, list))
        {
          dbus_free (list);
          return NULL;
        }
    }

  return list;
}

dbus_bool_t
bus_policy_append_user_rule (BusPolicy      *policy,
                             dbus_uid_t      uid,
                             BusPolicyRule  *rule)
{
  DBusList **list;

  list = get_list (policy->rules_by_uid, uid);

  if (list == NULL)
    return FALSE;

  if (!_dbus_list_append (list, rule))
    return FALSE;

  bus_policy_rule_ref (rule);

  return TRUE;
}

dbus_bool_t
bus_policy_append_group_rule (BusPolicy      *policy,
                              dbus_gid_t      gid,
                              BusPolicyRule  *rule)
{
  DBusList **list;

  list = get_list (policy->rules_by_gid, gid);

  if (list == NULL)
    return FALSE;

  if (!_dbus_list_append (list, rule))
    return FALSE;

  bus_policy_rule_ref (rule);

  return TRUE;
}

dbus_bool_t
bus_policy_append_console_rule (BusPolicy      *policy,
                                dbus_bool_t     at_console,
                                BusPolicyRule  *rule)
{
  if (at_console)
    {
      if (!_dbus_list_append (&policy->at_console_true_rules, rule))
        return FALSE;
    }
    else
    {
      if (!_dbus_list_append (&policy->at_console_false_rules, rule))
        return FALSE;
    }

  bus_policy_rule_ref (rule);

  return TRUE;

}

static dbus_bool_t
append_copy_of_policy_list (DBusList **list,
                            DBusList **to_append)
{
  DBusList *link;
  DBusList *tmp_list;

  tmp_list = NULL;

  /* Preallocate all our links */
  link = _dbus_list_get_first_link (to_append);
  while (link != NULL)
    {
      if (!_dbus_list_append (&tmp_list, link->data))
        {
          _dbus_list_clear (&tmp_list);
          return FALSE;
        }
      
      link = _dbus_list_get_next_link (to_append, link);
    }

  /* Now append them */
  while ((link = _dbus_list_pop_first_link (&tmp_list)))
    {
      bus_policy_rule_ref (link->data);
      _dbus_list_append_link (list, link);
    }

  return TRUE;
}

static dbus_bool_t
merge_id_hash (DBusHashTable *dest,
               DBusHashTable *to_absorb)
{
  DBusHashIter iter;
  
  _dbus_hash_iter_init (to_absorb, &iter);
  while (_dbus_hash_iter_next (&iter))
    {
      unsigned long id = _dbus_hash_iter_get_uintptr_key (&iter);
      DBusList **list = _dbus_hash_iter_get_value (&iter);
      DBusList **target = get_list (dest, id);

      if (target == NULL)
        return FALSE;

      if (!append_copy_of_policy_list (target, list))
        return FALSE;
    }

  return TRUE;
}

static dbus_bool_t
merge_string_hash (unsigned int *n_rules,
                   unsigned int n_rules_to_absorb,
                   DBusHashTable *dest,
                   DBusHashTable *to_absorb)
{
  DBusHashIter iter;
#ifndef DBUS_DISABLE_ASSERT
  unsigned cnt_rules = 0;
#endif

  _dbus_hash_iter_init (to_absorb, &iter);
  while (_dbus_hash_iter_next (&iter))
    {
      const char *id = _dbus_hash_iter_get_string_key (&iter);
      BusPolicyRulesWithScore *to_absorb_rules =_dbus_hash_iter_get_value (&iter);
      DBusList **list = &to_absorb_rules->rules;
      BusPolicyRulesWithScore *target_rules = get_rules_by_string (dest, id);
      DBusList **target;
      DBusList *list_iter;
      DBusList *target_first_link;

      if (target_rules == NULL)
        return FALSE;

      target = &target_rules->rules;
      target_first_link = _dbus_list_get_first_link (target);

      list_iter = _dbus_list_get_first_link (list);
      while (list_iter != NULL)
        {
          DBusList *new_link;
          BusPolicyRule *rule = list_iter->data;

          rule->score += *n_rules;
          list_iter = _dbus_list_get_next_link (list, list_iter);
#ifndef DBUS_DISABLE_ASSERT
          cnt_rules++;
#endif
          new_link = _dbus_list_alloc_link (rule);
          if (new_link == NULL)
            return FALSE;

          bus_policy_rule_ref (rule);

          _dbus_list_insert_before_link (target, target_first_link, new_link);
        }

      target_rules->score = to_absorb_rules->score + *n_rules;
    }

  _dbus_assert (n_rules_to_absorb == cnt_rules);

  *n_rules += n_rules_to_absorb;

  return TRUE;
}

dbus_bool_t
bus_policy_merge (BusPolicy *policy,
                  BusPolicy *to_absorb)
{
  /* FIXME Not properly atomic, but as used for configuration files we
   * don't rely on it quite so much.
   */
  
  if (!append_copy_of_policy_list (&policy->default_rules,
                                   &to_absorb->default_rules))
    return FALSE;
  
  if (!append_copy_of_policy_list (&policy->mandatory_rules,
                                   &to_absorb->mandatory_rules))
    return FALSE;

  if (!append_copy_of_policy_list (&policy->at_console_true_rules,
                                   &to_absorb->at_console_true_rules))
    return FALSE;

  if (!append_copy_of_policy_list (&policy->at_console_false_rules,
                                   &to_absorb->at_console_false_rules))
    return FALSE;

  if (!merge_id_hash (policy->rules_by_uid,
                      to_absorb->rules_by_uid))
    return FALSE;
  
  if (!merge_id_hash (policy->rules_by_gid,
                      to_absorb->rules_by_gid))
    return FALSE;

  if (!merge_string_hash (&policy->n_default_rules,
                          to_absorb->n_default_rules,
                          policy->default_rules_by_name,
                          to_absorb->default_rules_by_name))
    return FALSE;

  if (!append_copy_of_policy_list (&policy->default_prefix_rules,
                                   &to_absorb->default_prefix_rules))
    return FALSE;

  return TRUE;
}

BusClientPolicy*
bus_client_policy_new (void)
{
  BusClientPolicy *policy;

  policy = dbus_new0 (BusClientPolicy, 1);
  if (policy == NULL)
    return NULL;

  policy->refcount = 1;

  return policy;
}

BusClientPolicy *
bus_client_policy_ref (BusClientPolicy *policy)
{
  _dbus_assert (policy->refcount > 0);

  policy->refcount += 1;

  return policy;
}

void
bus_client_policy_unref (BusClientPolicy *policy)
{
  _dbus_assert (policy->refcount > 0);

  policy->refcount -= 1;

  if (policy->refcount == 0)
    {
      if (policy->policy)
        bus_policy_unref (policy->policy);

      dbus_free (policy->groups);

      dbus_free (policy);
    }
}

typedef struct SendReceiveParams {
    BusRegistry    *registry;
    dbus_bool_t     requested_reply;
    DBusConnection *peer;
    DBusMessage    *message;
    dbus_bool_t     eavesdropping;
} SendReceiveParams;

typedef struct OwnParams {
    const DBusString *name;
} OwnParams;

typedef struct RuleParams {
  enum {PARAMS_OWN, PARAMS_SEND, PARAMS_RECEIVE} type;
  union {
    SendReceiveParams sr;
    OwnParams         own;
  } u;
} RuleParams;

static dbus_bool_t
check_send_rule (const BusPolicyRule     *rule,
                 const SendReceiveParams *match_params)
{
  /* Rule is skipped if it specifies a different
   * message name from the message, or a different
   * destination from the message
   */
  if (rule->type != BUS_POLICY_RULE_SEND)
    {
      _dbus_verbose ("  (policy) skipping non-send rule\n");
      return FALSE;
    }

  if (rule->d.send.message_type != DBUS_MESSAGE_TYPE_INVALID)
    {
      if (dbus_message_get_type (match_params->message) != rule->d.send.message_type)
        {
          _dbus_verbose ("  (policy) skipping rule for different message type\n");
          return FALSE;
        }
    }

  /* If it's a reply, the requested_reply flag kicks in */
  if (dbus_message_get_reply_serial (match_params->message) != 0)
    {
      /* for allow, requested_reply=true means the rule applies
       * only when reply was requested. requested_reply=false means
       * always allow.
       */
      if (!match_params->requested_reply && rule->allow && rule->d.send.requested_reply && !rule->d.send.eavesdrop)
        {
          _dbus_verbose ("  (policy) skipping allow rule since it only applies to requested replies and does not allow eavesdropping\n");
          return FALSE;
        }

      /* for deny, requested_reply=false means the rule applies only
       * when the reply was not requested. requested_reply=true means the
       * rule always applies.
       */
      if (match_params->requested_reply && !rule->allow && !rule->d.send.requested_reply)
        {
          _dbus_verbose ("  (policy) skipping deny rule since it only applies to unrequested replies\n");
          return FALSE;
        }
    }

  if (rule->d.send.path != NULL)
    {
      if (dbus_message_get_path (match_params->message) != NULL &&
          strcmp (dbus_message_get_path (match_params->message),
                  rule->d.send.path) != 0)
        {
          _dbus_verbose ("  (policy) skipping rule for different path\n");
          return FALSE;
        }
    }

  if (rule->d.send.interface != NULL)
    {
      /* The interface is optional in messages. For allow rules, if the message
       * has no interface we want to skip the rule (and thus not allow);
       * for deny rules, if the message has no interface we want to use the
       * rule (and thus deny).
       */
      dbus_bool_t no_interface;

      no_interface = dbus_message_get_interface (match_params->message) == NULL;
      
      if ((no_interface && rule->allow) ||
          (!no_interface &&
           strcmp (dbus_message_get_interface (match_params->message),
                   rule->d.send.interface) != 0))
        {
          _dbus_verbose ("  (policy) skipping rule for different interface\n");
          return FALSE;
        }
    }

  if (rule->d.send.member != NULL)
    {
      if (dbus_message_get_member (match_params->message) != NULL &&
          strcmp (dbus_message_get_member (match_params->message),
                  rule->d.send.member) != 0)
        {
          _dbus_verbose ("  (policy) skipping rule for different member\n");
          return FALSE;
        }
    }

  if (rule->d.send.error != NULL)
    {
      if (dbus_message_get_error_name (match_params->message) != NULL &&
          strcmp (dbus_message_get_error_name (match_params->message),
                  rule->d.send.error) != 0)
        {
          _dbus_verbose ("  (policy) skipping rule for different error name\n");
          return FALSE;
        }
    }

  if (rule->d.send.broadcast != BUS_POLICY_TRISTATE_ANY)
    {
      if (dbus_message_get_destination (match_params->message) == NULL &&
          dbus_message_get_type (match_params->message) == DBUS_MESSAGE_TYPE_SIGNAL)
        {
          /* it's a broadcast */
          if (rule->d.send.broadcast == BUS_POLICY_TRISTATE_FALSE)
            {
              _dbus_verbose ("  (policy) skipping rule because message is a broadcast\n");
              return FALSE;
            }
        }
      /* else it isn't a broadcast: there is some destination */
      else if (rule->d.send.broadcast == BUS_POLICY_TRISTATE_TRUE)
        {
          _dbus_verbose ("  (policy) skipping rule because message is not a broadcast\n");
          return FALSE;
        }
    }

  if (rule->d.send.destination != NULL && !rule->d.send.destination_is_prefix)
    {
      /* receiver can be NULL for messages that are sent to the
       * message bus itself, we check the strings in that case as
       * built-in services don't have a DBusConnection but messages
       * to them have a destination service name.
       *
       * Similarly, receiver can be NULL when we're deciding whether
       * activation should be allowed; we make the authorization decision
       * on the assumption that the activated service will have the
       * requested name and no others.
       */
      if (match_params->peer == NULL)
        {
          if (!dbus_message_has_destination (match_params->message,
                                             rule->d.send.destination))
            {
              _dbus_verbose ("  (policy) skipping rule because message dest is not %s\n",
                             rule->d.send.destination);
              return FALSE;
            }
        }
      else
        {
          DBusString str;
          BusService *service;

          _dbus_string_init_const (&str, rule->d.send.destination);

          service = bus_registry_lookup (match_params->registry, &str);
          if (service == NULL)
            {
              _dbus_verbose ("  (policy) skipping rule because dest %s doesn't exist\n",
                             rule->d.send.destination);
              return FALSE;
            }

          if (!bus_service_owner_in_queue (service, match_params->peer))
            {
              _dbus_verbose ("  (policy) skipping rule because receiver isn't primary or queued owner of name %s\n",
                             rule->d.send.destination);
              return FALSE;
            }
        }
    }

  if (rule->d.send.destination != NULL && rule->d.send.destination_is_prefix)
    {
      /* receiver can be NULL - the same as in !send.destination_is_prefix */
      if (match_params->peer == NULL)
        {
          const char *destination = dbus_message_get_destination (match_params->message);
          DBusString dest_name;

          if (destination == NULL)
            {
              _dbus_verbose ("  (policy) skipping rule because message has no dest\n");
              return FALSE;
            }

          _dbus_string_init_const (&dest_name, destination);

          if (!_dbus_string_starts_with_words_c_str (&dest_name,
                                                     rule->d.send.destination,
                                                     '.'))
            {
              _dbus_verbose ("  (policy) skipping rule because message dest doesn't have prefix %s\n",
                             rule->d.send.destination);
              return FALSE;
            }
        }
      else
        {
          if (!bus_connection_is_queued_owner_by_prefix (match_params->peer,
                                                         rule->d.send.destination))
            {
              _dbus_verbose ("  (policy) skipping rule because recipient isn't primary or queued owner of any name below %s\n",
                             rule->d.send.destination);
              return FALSE;
            }
        }
    }

  if (rule->d.send.min_fds > 0 ||
      rule->d.send.max_fds < DBUS_MAXIMUM_MESSAGE_UNIX_FDS)
    {
      unsigned int n_fds = _dbus_message_get_n_unix_fds (match_params->message);

      if (n_fds < rule->d.send.min_fds || n_fds > rule->d.send.max_fds)
        {
          _dbus_verbose ("  (policy) skipping rule because message has %u fds "
                         "and that is outside range [%u,%u]",
                         n_fds, rule->d.send.min_fds, rule->d.send.max_fds);
          return FALSE;
        }
    }

  /* Use this rule */
  return TRUE;
}

static dbus_bool_t
check_receive_rule (const BusPolicyRule     *rule,
                    const SendReceiveParams *match_params)
{
  if (rule->type != BUS_POLICY_RULE_RECEIVE)
    {
      _dbus_verbose ("  (policy) skipping non-receive rule\n");
      return FALSE;
    }

  if (rule->d.receive.message_type != DBUS_MESSAGE_TYPE_INVALID)
    {
      if (dbus_message_get_type (match_params->message) != rule->d.receive.message_type)
        {
          _dbus_verbose ("  (policy) skipping rule for different message type\n");
          return FALSE;
        }
    }

  /* for allow, eavesdrop=false means the rule doesn't apply when
   * eavesdropping. eavesdrop=true means always allow.
   */
  if (match_params->eavesdropping && rule->allow && !rule->d.receive.eavesdrop)
    {
      _dbus_verbose ("  (policy) skipping allow rule since it doesn't apply to eavesdropping\n");
      return FALSE;
    }

  /* for deny, eavesdrop=true means the rule applies only when
   * eavesdropping; eavesdrop=false means always deny.
   */
  if (!match_params->eavesdropping && !rule->allow && rule->d.receive.eavesdrop)
    {
      _dbus_verbose ("  (policy) skipping deny rule since it only applies to eavesdropping\n");
      return FALSE;
    }

  /* If it's a reply, the requested_reply flag kicks in */
  if (dbus_message_get_reply_serial (match_params->message) != 0)
    {
      /* for allow, requested_reply=true means the rule applies
       * only when reply was requested. requested_reply=false means
       * always allow.
       */
      if (!match_params->requested_reply && rule->allow && rule->d.receive.requested_reply && !rule->d.receive.eavesdrop)
        {
          _dbus_verbose ("  (policy) skipping allow rule since it only applies to requested replies and does not allow eavesdropping\n");
          return FALSE;
        }

      /* for deny, requested_reply=false means the rule applies only
       * when the reply was not requested. requested_reply=true means the
       * rule always applies.
       */
      if (match_params->requested_reply && !rule->allow && !rule->d.receive.requested_reply)
        {
          _dbus_verbose ("  (policy) skipping deny rule since it only applies to unrequested replies\n");
          return FALSE;
        }
    }

  if (rule->d.receive.path != NULL)
    {
      if (dbus_message_get_path (match_params->message) != NULL &&
          strcmp (dbus_message_get_path (match_params->message),
                  rule->d.receive.path) != 0)
        {
          _dbus_verbose ("  (policy) skipping rule for different path\n");
          return FALSE;
        }
    }

  if (rule->d.receive.interface != NULL)
    {
      /* The interface is optional in messages. For allow rules, if the message
       * has no interface we want to skip the rule (and thus not allow);
       * for deny rules, if the message has no interface we want to use the
       * rule (and thus deny).
       */
      dbus_bool_t no_interface;

      no_interface = dbus_message_get_interface (match_params->message) == NULL;

      if ((no_interface && rule->allow) ||
          (!no_interface &&
           strcmp (dbus_message_get_interface (match_params->message),
                   rule->d.receive.interface) != 0))
        {
          _dbus_verbose ("  (policy) skipping rule for different interface\n");
          return FALSE;
        }
    }

  if (rule->d.receive.member != NULL)
    {
      if (dbus_message_get_member (match_params->message) != NULL &&
          strcmp (dbus_message_get_member (match_params->message),
                  rule->d.receive.member) != 0)
        {
          _dbus_verbose ("  (policy) skipping rule for different member\n");
          return FALSE;
        }
    }

  if (rule->d.receive.error != NULL)
    {
      if (dbus_message_get_error_name (match_params->message) != NULL &&
          strcmp (dbus_message_get_error_name (match_params->message),
                  rule->d.receive.error) != 0)
        {
          _dbus_verbose ("  (policy) skipping rule for different error name\n");
          return FALSE;
        }
    }

  if (rule->d.receive.origin != NULL)
    {
      /* sender can be NULL for messages that originate from the
       * message bus itself, we check the strings in that case as
       * built-in services don't have a DBusConnection but will
       * still set the sender on their messages.
       */
      if (match_params->peer == NULL)
        {
          if (!dbus_message_has_sender (match_params->message,
                                        rule->d.receive.origin))
            {
              _dbus_verbose ("  (policy) skipping rule because message sender is not %s\n",
                             rule->d.receive.origin);
              return FALSE;
            }
        }
      else
        {
          BusService *service;
          DBusString str;

          _dbus_string_init_const (&str, rule->d.receive.origin);

          service = bus_registry_lookup (match_params->registry, &str);
          
          if (service == NULL)
            {
              _dbus_verbose ("  (policy) skipping rule because origin %s doesn't exist\n",
                             rule->d.receive.origin);
              return FALSE;
            }

          if (!bus_service_owner_in_queue (service, match_params->peer))
            {
              _dbus_verbose ("  (policy) skipping rule because sender isn't primary or queued owner of %s\n",
                             rule->d.receive.origin);
              return FALSE;
            }
        }
    }

  if (rule->d.receive.min_fds > 0 ||
      rule->d.receive.max_fds < DBUS_MAXIMUM_MESSAGE_UNIX_FDS)
    {
      unsigned int n_fds = _dbus_message_get_n_unix_fds (match_params->message);

      if (n_fds < rule->d.receive.min_fds || n_fds > rule->d.receive.max_fds)
        {
          _dbus_verbose ("  (policy) skipping rule because message has %u fds "
                         "and that is outside range [%u,%u]",
                         n_fds, rule->d.receive.min_fds,
                         rule->d.receive.max_fds);
          return FALSE;
        }
    }

  /* Use this rule */
  return TRUE;
}

static dbus_bool_t
check_own_rule (const BusPolicyRule *rule,
                const OwnParams     *params)
{
  const DBusString *service_name = params->name;

  /* Rule is skipped if it specifies a different service name from
   * the desired one.
   */

  if (rule->type != BUS_POLICY_RULE_OWN)
    return FALSE;

  if (!rule->d.own.prefix && rule->d.own.service_name != NULL)
    {
      if (!_dbus_string_equal_c_str (service_name,
                                     rule->d.own.service_name))
        return FALSE;
    }
  else if (rule->d.own.prefix)
    {
      if (!_dbus_string_starts_with_words_c_str (service_name,
                                                 rule->d.own.service_name,
                                                 '.'))
        return FALSE;
    }

  /* Use this rule */
  return TRUE;
}

static dbus_bool_t
check_rules_list (const DBusList       *rules,
                  dbus_bool_t           allowed_current,
                  const RuleParams     *params,
                  dbus_int32_t         *toggles,
                  dbus_bool_t          *log,
                  const BusPolicyRule **matched_rule,
                  dbus_bool_t           break_on_first_match)
{
  const DBusList *link;
  dbus_bool_t allowed;

  allowed = allowed_current;

  link = _dbus_list_get_first_link ((DBusList **)&rules);
  while (link != NULL)
    {
      const BusPolicyRule *rule = link->data;
      dbus_bool_t matches;

      link = _dbus_list_get_next_link ((DBusList **)&rules, link);

      switch (params->type)
        {
          case PARAMS_OWN:
            matches = check_own_rule (rule, &params->u.own);
            break;
          case PARAMS_SEND:
            matches = check_send_rule (rule, &params->u.sr);
            break;
          case PARAMS_RECEIVE:
            matches = check_receive_rule (rule, &params->u.sr);
            break;
          default:
            _dbus_assert_not_reached ("wrong type of policy");
        }

      if (matches)
        {
          if (log)
            *log = rule->d.send.log;
          if (toggles)
            (*toggles)++;
          if (matched_rule)
            *matched_rule = rule;
          allowed = rule->allow;

          _dbus_verbose ("  (policy) used rule, allow now = %d\n",
                         allowed);

          if (break_on_first_match)
            break;
        }
    }
  return allowed;
}

static int
check_rules_list_with_score (DBusList             *rules,
                             int                   score,
                             const RuleParams     *params,
                             dbus_int32_t         *toggles,
                             dbus_bool_t          *log,
                             const BusPolicyRule **matched_rule,
                             dbus_bool_t           break_on_first_match)
{
  dbus_int32_t local_toggles;
  dbus_bool_t local_log;
  const BusPolicyRule *local_matched_rule;

  local_toggles = 0;

  check_rules_list (rules,
                    FALSE,
                    params,
                    &local_toggles,
                    &local_log,
                    &local_matched_rule,
                    break_on_first_match);

  if (local_toggles > 0)
    {
      _dbus_assert (local_matched_rule != NULL);

      if (local_matched_rule->score > score)
        {
          if (toggles)
            *toggles += local_toggles;
          if (log)
            *log = local_log;
          if (matched_rule)
            *matched_rule = local_matched_rule;
          return local_matched_rule->score;
        }
    }

  return score;
}

static int
check_rules_for_name (DBusHashTable        *rules,
                      const char           *name,
                      int                   score,
                      const RuleParams     *params,
                      dbus_int32_t         *toggles,
                      dbus_bool_t          *log,
                      const BusPolicyRule **matched_rule)
{
  const BusPolicyRulesWithScore *rules_list;

  rules_list = _dbus_hash_table_lookup_string (rules, name);

  if (rules_list == NULL || rules_list->score <= score)
    return score;

  return check_rules_list_with_score (rules_list->rules, score, params, toggles, log, matched_rule, TRUE);
}

static int
find_and_check_rules_for_name (DBusHashTable        *rules,
                               DBusList             *prefix_rules,
                               const char           *c_str,
                               int                   score,
                               const RuleParams     *params,
                               dbus_int32_t         *toggles,
                               dbus_bool_t          *log,
                               const BusPolicyRule **matched_rule)
{
  score = check_rules_for_name (rules, c_str,
                                score, params,
                                toggles, log,
                                matched_rule);

  score = check_rules_list_with_score (prefix_rules,
                                       score, params,
                                       toggles, log,
                                       matched_rule, FALSE);

  return score;
}

static dbus_bool_t
find_and_check_rules (DBusHashTable    *rules,
                      DBusList         *prefix_rules,
                      const RuleParams *params,
                      dbus_int32_t     *toggles,
                      dbus_bool_t      *log)
{
  dbus_bool_t allowed;
  const DBusList *services = NULL;
  const BusPolicyRule *matched_rule = NULL;
  int score = 0;

  allowed = FALSE;

  if (params->type == PARAMS_SEND || params->type == PARAMS_RECEIVE)
    {
      if (params->u.sr.peer != NULL)
        {
          DBusList *link;

          services = bus_connection_get_owned_services_list (params->u.sr.peer);

          link = _dbus_list_get_first_link ((DBusList **)&services);
          while (link != NULL)
            {
              const char *name = bus_service_get_name (link->data);

              link = _dbus_list_get_next_link ((DBusList **)&services, link);

              /* skip unique id names */
              if (name[0] == ':')
                continue;

              score = find_and_check_rules_for_name (rules, prefix_rules, name, score,
                                                     params, toggles, log, &matched_rule);
            }
        }
      else
        {
          /* NULL peer means dbus-daemon or activation */
          const char *rule_target_name;

          if (params->type == PARAMS_SEND)
            rule_target_name = dbus_message_get_destination (params->u.sr.message);
          else if (params->type == PARAMS_RECEIVE)
            rule_target_name = dbus_message_get_sender (params->u.sr.message);

          if (rule_target_name != NULL)
            score = find_and_check_rules_for_name (rules, prefix_rules, rule_target_name, score,
                                                   params, toggles, log, &matched_rule);
        }
    }
  else
    score = find_and_check_rules_for_name (rules, prefix_rules, _dbus_string_get_const_data(params->u.own.name),
                                           score, params, toggles, log, &matched_rule);

  /* check also wildcard rules */
  check_rules_for_name (rules, "", score, params, toggles, log, &matched_rule);

  if (matched_rule)
    allowed = matched_rule->allow;

  return allowed;
}

static dbus_bool_t
check_policy (BusClientPolicy  *policy,
              const RuleParams *params,
              dbus_int32_t     *toggles,
              dbus_bool_t      *log)
{
  dbus_bool_t allowed;

  if (toggles)
    *toggles = 0;

  allowed = find_and_check_rules (policy->policy->default_rules_by_name,
                                  policy->policy->default_prefix_rules,
                                  params,
                                  toggles,
                                  log);

  _dbus_verbose("checked, allow now = %d\n", allowed);

  /* we avoid the overhead of looking up user's groups
   * if we don't have any group rules anyway
   */
  if (_dbus_hash_table_get_n_entries (policy->policy->rules_by_gid) > 0)
    {
      int i;

      for (i = 0; i < policy->n_groups; ++i)
        {
          const DBusList **list;

          list = _dbus_hash_table_lookup_uintptr (policy->policy->rules_by_gid,
                                                  policy->groups[i]);

          if (list != NULL)
            allowed = check_rules_list (*list, allowed, params, toggles, log, NULL, FALSE);
        }
    }

  if (policy->uid_set)
    {
      if (_dbus_hash_table_get_n_entries (policy->policy->rules_by_uid) > 0)
        {
          const DBusList **list;

          list = _dbus_hash_table_lookup_uintptr (policy->policy->rules_by_uid,
                                                  policy->uid);

          if (list != NULL)
            allowed = check_rules_list (*list, allowed, params, toggles, log, NULL, FALSE);

          if (policy->at_console)
            allowed = check_rules_list (policy->policy->at_console_true_rules,
                                        allowed,
                                        params,
                                        toggles,
                                        log,
                                        NULL,
                                        FALSE);
          else
            allowed = check_rules_list (policy->policy->at_console_false_rules,
                                        allowed,
                                        params,
                                        toggles,
                                        log,
                                        NULL,
                                        FALSE);
        }
    }

  allowed = check_rules_list (policy->policy->mandatory_rules,
                              allowed,
                              params,
                              toggles,
                              log,
                              NULL,
                              FALSE);

  return allowed;
}

dbus_bool_t
bus_client_policy_check_can_send (BusClientPolicy *policy,
                                  BusRegistry     *registry,
                                  dbus_bool_t      requested_reply,
                                  DBusConnection  *receiver,
                                  DBusMessage     *message,
                                  dbus_int32_t    *toggles,
                                  dbus_bool_t     *log)
{
  struct RuleParams params;

  params.type = PARAMS_SEND;
  params.u.sr.registry = registry;
  params.u.sr.requested_reply = requested_reply;
  params.u.sr.peer = receiver;
  params.u.sr.message = message;

  _dbus_verbose ("  (policy) checking send rules\n");

  return check_policy (policy, &params, toggles, log);
}

/* See docs on what the args mean on bus_context_check_security_policy()
 * comment
 */
dbus_bool_t
bus_client_policy_check_can_receive (BusClientPolicy *policy,
                                     BusRegistry     *registry,
                                     dbus_bool_t      requested_reply,
                                     DBusConnection  *sender,
                                     DBusConnection  *addressed_recipient,
                                     DBusConnection  *proposed_recipient,
                                     DBusMessage     *message,
                                     dbus_int32_t    *toggles)
{
  struct RuleParams params;

  params.type = PARAMS_RECEIVE;
  params.u.sr.registry = registry;
  params.u.sr.requested_reply = requested_reply;
  params.u.sr.peer = sender;
  params.u.sr.message = message;
  params.u.sr.eavesdropping =
    addressed_recipient != proposed_recipient &&
    dbus_message_get_destination (message) != NULL;

  _dbus_verbose ("  (policy) checking receive rules, eavesdropping = %d\n", params.u.sr.eavesdropping);

  return check_policy (policy, &params, toggles, NULL);
}

dbus_bool_t
bus_client_policy_check_can_own (BusClientPolicy  *policy,
                                 const DBusString *service_name)
{
  RuleParams params;
  params.type = PARAMS_OWN;
  params.u.own.name = service_name;

  return check_policy (policy, &params, NULL, NULL);
}

#ifdef DBUS_ENABLE_EMBEDDED_TESTS
dbus_bool_t
bus_policy_check_can_own (BusPolicy  *policy,
                          const DBusString *service_name)
{
  RuleParams params;
  params.type = PARAMS_OWN;
  params.u.own.name = service_name;

  return find_and_check_rules (policy->default_rules_by_name,
                               policy->default_prefix_rules,
                               &params,
                               NULL,
                               NULL);
}
#endif /* DBUS_ENABLE_EMBEDDED_TESTS */
