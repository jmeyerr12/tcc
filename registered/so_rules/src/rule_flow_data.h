//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// rule_flow_data.h author Brandon Stultz <brastult@cisco.com>

#ifndef RULE_FLOW_DATA_H
#define RULE_FLOW_DATA_H

#include "flow/flow.h"
#include "framework/base_api.h"

#if(BASE_API_VERSION > 23)
#define FD_TYPE FlowData
#define FD_ARGS(id,name) id,name
#else
#define FD_TYPE RuleFlowData
#define FD_ARGS(id,name) id
#endif

#endif
