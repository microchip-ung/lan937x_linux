/**
 * @file tlv.h
 * @brief Implements helper routines for processing Type Length Value fields.
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef HAVE_TLV_H
#define HAVE_TLV_H

#include "ddt.h"
#include "ds.h"

/* TLV types */
#define TLV_MANAGEMENT					0x0001
#define TLV_MANAGEMENT_ERROR_STATUS			0x0002
#define TLV_ORGANIZATION_EXTENSION			0x0003
#define TLV_REQUEST_UNICAST_TRANSMISSION		0x0004
#define TLV_GRANT_UNICAST_TRANSMISSION			0x0005
#define TLV_CANCEL_UNICAST_TRANSMISSION			0x0006
#define TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION	0x0007
#define TLV_PATH_TRACE					0x0008
#define TLV_ALTERNATE_TIME_OFFSET_INDICATOR		0x0009
#define TLV_AUTHENTICATION				0x2000
#define TLV_AUTHENTICATION_CHALLENGE			0x2001
#define TLV_SECURITY_ASSOCIATION_UPDATE			0x2002
#define TLV_CUM_FREQ_SCALE_FACTOR_OFFSET		0x2003

enum management_action {
	GET,
	SET,
	RESPONSE,
	COMMAND,
	ACKNOWLEDGE,
};

/* Clock management ID values */
#define TLV_USER_DESCRIPTION				0x0002
#define TLV_SAVE_IN_NON_VOLATILE_STORAGE		0x0003
#define TLV_RESET_NON_VOLATILE_STORAGE			0x0004
#define TLV_INITIALIZE					0x0005
#define TLV_FAULT_LOG					0x0006
#define TLV_FAULT_LOG_RESET				0x0007
#define TLV_DEFAULT_DATA_SET				0x2000
#define TLV_CURRENT_DATA_SET				0x2001
#define TLV_PARENT_DATA_SET				0x2002
#define TLV_TIME_PROPERTIES_DATA_SET			0x2003
#define TLV_PRIORITY1					0x2005
#define TLV_PRIORITY2					0x2006
#define TLV_DOMAIN					0x2007
#define TLV_SLAVE_ONLY					0x2008
#define TLV_TIME					0x200F
#define TLV_CLOCK_ACCURACY				0x2010
#define TLV_UTC_PROPERTIES				0x2011
#define TLV_TRACEABILITY_PROPERTIES			0x2012
#define TLV_TIMESCALE_PROPERTIES			0x2013
#define TLV_PATH_TRACE_LIST				0x2015
#define TLV_PATH_TRACE_ENABLE				0x2016
#define TLV_GRANDMASTER_CLUSTER_TABLE			0x2017
#define TLV_ACCEPTABLE_MASTER_TABLE			0x201A
#define TLV_ACCEPTABLE_MASTER_MAX_TABLE_SIZE		0x201C
#define TLV_ALTERNATE_TIME_OFFSET_ENABLE		0x201E
#define TLV_ALTERNATE_TIME_OFFSET_NAME			0x201F
#define TLV_ALTERNATE_TIME_OFFSET_MAX_KEY		0x2020
#define TLV_ALTERNATE_TIME_OFFSET_PROPERTIES		0x2021
#define TLV_TRANSPARENT_CLOCK_DEFAULT_DATA_SET		0x4000
#define TLV_PRIMARY_DOMAIN				0x4002
#define TLV_TIME_STATUS_NP				0xC000
#define TLV_GRANDMASTER_SETTINGS_NP			0xC001
#define TLV_SUBSCRIBE_EVENTS_NP				0xC003

/* Port management ID values */
#define TLV_NULL_MANAGEMENT				0x0000
#define TLV_CLOCK_DESCRIPTION				0x0001
#define TLV_PORT_DATA_SET				0x2004
#define TLV_LOG_ANNOUNCE_INTERVAL			0x2009
#define TLV_ANNOUNCE_RECEIPT_TIMEOUT			0x200A
#define TLV_LOG_SYNC_INTERVAL				0x200B
#define TLV_VERSION_NUMBER				0x200C
#define TLV_ENABLE_PORT					0x200D
#define TLV_DISABLE_PORT				0x200E
#define TLV_UNICAST_NEGOTIATION_ENABLE			0x2014
#define TLV_UNICAST_MASTER_TABLE			0x2018
#define TLV_UNICAST_MASTER_MAX_TABLE_SIZE		0x2019
#define TLV_ACCEPTABLE_MASTER_TABLE_ENABLED		0x201B
#define TLV_ALTERNATE_MASTER				0x201D
#define TLV_TRANSPARENT_CLOCK_PORT_DATA_SET		0x4001
#define TLV_DELAY_MECHANISM				0x6000
#define TLV_LOG_MIN_PDELAY_REQ_INTERVAL			0x6001
#define TLV_PORT_DATA_SET_NP				0xC002
#define TLV_PORT_PROPERTIES_NP				0xC004

#ifdef KSZ_1588_PTP
#define TLV_MASTER_ONLY					0x8001
#define TLV_INITIAL_LOG_PDELAY_REQ_INTERVAL		0x8002
#define TLV_OPER_LOG_PDELAY_REQ_INTERVAL		0x8003
#define TLV_INITIAL_LOG_SYNC_INTERVAL			0x8004
#define TLV_OPER_LOG_SYNC_INTERVAL			0x8005
#define TLV_NEIGHBOR_PROP_DELAY				0x8007
#define TLV_WAKE_INFO					0x8008
#define TLV_INTERVAL_INFO				0x9001
#endif

/* Management error ID values */
#define TLV_RESPONSE_TOO_BIG				0x0001
#define TLV_NO_SUCH_ID					0x0002
#define TLV_WRONG_LENGTH				0x0003
#define TLV_WRONG_VALUE					0x0004
#define TLV_NOT_SETABLE					0x0005
#define TLV_NOT_SUPPORTED				0x0006
#define TLV_GENERAL_ERROR				0xFFFE

struct management_tlv {
	Enumeration16 type;
	UInteger16    length;
	Enumeration16 id;
	Octet         data[0];
} PACKED;

struct management_tlv_datum {
	uint8_t val;
	uint8_t reserved;
} PACKED;

struct management_error_status {
	Enumeration16 type;
	UInteger16    length;
	Enumeration16 error;
	Enumeration16 id;
	Octet         reserved[4];
	Octet         data[0];
} PACKED;

/* Organizationally Unique Identifiers */
#define IEEE_802_1_COMMITTEE 0x00, 0x80, 0xC2
extern uint8_t ieee8021_id[3];
#ifdef KSZ_1588_PTP
#define IEEE_C37_238 0x1C, 0x12, 0x9D
extern uint8_t ieee_c37_238_id[3];
#endif

struct organization_tlv {
	Enumeration16 type;
	UInteger16    length;
	Octet         id[3];
	Octet         subtype[3];
} PACKED;

#define PATH_TRACE_MAX \
	((sizeof(struct message_data) - sizeof(struct announce_msg) - sizeof(struct TLV)) / \
	 sizeof(struct ClockIdentity))

struct path_trace_tlv {
	Enumeration16 type;
	UInteger16    length;
	struct ClockIdentity cid[0];
} PACKED;

static inline unsigned int path_length(struct path_trace_tlv *p)
{
	return p->length / sizeof(struct ClockIdentity);
}

typedef struct Integer96 {
	uint16_t nanoseconds_msb;
	uint64_t nanoseconds_lsb;
	uint16_t fractional_nanoseconds;
} PACKED ScaledNs;

struct follow_up_info_tlv {
	Enumeration16 type;
	UInteger16    length;
	Octet         id[3];
	Octet         subtype[3];
	Integer32     cumulativeScaledRateOffset;
	UInteger16    gmTimeBaseIndicator;
	ScaledNs      lastGmPhaseChange;
	Integer32     scaledLastGmPhaseChange;
} PACKED;

struct time_status_np {
	int64_t       master_offset; /*nanoseconds*/
	int64_t       ingress_time;  /*nanoseconds*/
	Integer32     cumulativeScaledRateOffset;
	Integer32     scaledLastGmPhaseChange;
	UInteger16    gmTimeBaseIndicator;
	ScaledNs      lastGmPhaseChange;
	Integer32     gmPresent;
	struct ClockIdentity gmIdentity;
} PACKED;

#ifdef KSZ_1588_PTP
struct interval_info_tlv {
	Enumeration16 type;
	UInteger16    length;
	Octet         id[3];
	Octet         subtype[3];
	int8_t	      linkDelayInterval;
	int8_t	      timeSyncInterval;
	int8_t	      announceInterval;
	uint8_t	      flags;
	uint16_t      reserved;
} PACKED;

struct wake_info_tlv {
	Enumeration16 type;
	UInteger16    length;
	Octet         id[3];
	Octet         subtype[3];
	uint8_t	      event;
} PACKED;

struct ieee_c37_238_data {
	UInteger16 grandmasterID;
	UInteger32 grandmasterTimeInaccuracy;
	UInteger32 networkTimeInaccuracy;
	UInteger16 reserved;
} PACKED;

struct ieee_c37_238_info_tlv {
	struct organization_tlv org;
	struct ieee_c37_238_data data;
} PACKED;

struct ptp_second {
	UInteger16 seconds_msb;
	UInteger32 seconds_lsb;
} PACKED;

struct ptp_text {
	UInteger8 lengthField;
	UInteger8 textField[1];
} PACKED;

struct tlv_hdr {
	Enumeration16 type;
	UInteger16 length;
} PACKED;

struct alternate_time_offset_tlv {
	struct tlv_hdr hdr;
	UInteger8 keyField;
	Integer32 currentOffset;
	Integer32 jumpSeconds;
	struct ptp_second timeOfNextJump;
	struct ptp_text displayName;
} PACKED;

struct transparent_clock_default_data_set {
	struct ClockIdentity clockIdentity;
	UInteger16 numberPorts;
	UInteger8 delayMechanism;
	UInteger8 primaryDomain;
} PACKED;

struct transparent_clock_port_data_set {
	struct PortIdentity portIdentity;
	UInteger8 faultyFlag:1;
	Integer8 logMinPdelayReqInterval;
	TimeInterval peerMeanPathDelay;
} PACKED;
#endif

struct grandmaster_settings_np {
	struct ClockQuality clockQuality;
	Integer16 utc_offset;
	UInteger8 time_flags;
	Enumeration8 time_source;
} PACKED;

struct port_ds_np {
	UInteger32    neighborPropDelayThresh; /*nanoseconds*/
	Integer32     asCapable;
} PACKED;


#define EVENT_BITMASK_CNT 64

struct subscribe_events_np {
	uint16_t      duration; /* seconds */
	uint8_t       bitmask[EVENT_BITMASK_CNT];
} PACKED;

struct port_properties_np {
	struct PortIdentity portIdentity;
	uint8_t port_state;
	uint8_t timestamping;
	struct PTPText interface;
} PACKED;

#define PROFILE_ID_LEN 6

struct mgmt_clock_description {
	UInteger16             *clockType;
	struct PTPText         *physicalLayerProtocol;
	struct PhysicalAddress *physicalAddress;
	struct PortAddress     *protocolAddress;
	Octet                  *manufacturerIdentity;
	struct PTPText         *productDescription;
	struct PTPText         *revisionData;
	struct PTPText         *userDescription;
	Octet                  *profileIdentity;
};

struct tlv_extra {
	union {
		struct mgmt_clock_description cd;
	};
};

/**
 * Converts recognized value sub-fields into host byte order.
 * @param tlv Pointer to a Type Length Value field.
 * @param extra Additional struct where data from tlv will be saved,
 * can be NULL.
 * @return Zero if successful, otherwise non-zero
 */
int tlv_post_recv(struct TLV *tlv, struct tlv_extra *extra);

/**
 * Converts recognized value sub-fields into network byte order.
 * @param tlv Pointer to a Type Length Value field.
 * @param extra Additional struct containing tlv data to send, can be
 * NULL.
 */
void tlv_pre_send(struct TLV *tlv, struct tlv_extra *extra);

#endif
