/******************************************************************************

  Copyright (c) 2009-2012, Intel Corporation 
  All rights reserved.
  
  Redistribution and use in source and binary forms, with or without 
  modification, are permitted provided that the following conditions are met:
  
   1. Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
  
   2. Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
  
   3. Neither the name of the Intel Corporation nor the names of its 
      contributors may be used to endorse or promote products derived from 
      this software without specific prior written permission.
  
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/

#include <ieee1588.hpp>

#include <avbts_clock.hpp>
#include <avbts_oslock.hpp>
#include <avbts_ostimerq.hpp>

#include <stdio.h>

#include <string.h>

#include <stdlib.h>

#include <string.h>
#include <time.h>

void ClockIdentity::set(LinkLayerAddress * addr)
{
	uint64_t tmp1 = 0;
	uint32_t tmp2;
	addr->toOctetArray((uint8_t *) & tmp1);
	tmp2 = tmp1 & 0xFFFFFF;
	tmp1 >>= 24;
	tmp1 <<= 16;
	tmp1 |= 0xFEFF;
	tmp1 <<= 24;
	tmp1 |= tmp2;
	memcpy(id, &tmp1, PTP_CLOCK_IDENTITY_LENGTH);
}

IEEE1588Clock::IEEE1588Clock
( bool forceOrdinarySlave, bool syntonize, uint8_t priority1,
  HWTimestamper *timestamper, OSTimerQueueFactory *timerq_factory,
  OS_IPC *ipc )
{
	timerq = timerq_factory->createOSTimerQueue();

	this->priority1 = priority1;
	priority2 = 248;

	number_ports = 0;

	this->forceOrdinarySlave = forceOrdinarySlave;

	clock_quality.clockAccuracy = 0xfe;
	clock_quality.cq_class = 248;
#ifdef MICREL_1588_PTP
	clock_quality.offsetScaledLogVariance = 0x436A;
#else
	clock_quality.offsetScaledLogVariance = 16640;
#endif

	time_source = 160;

	domain_number = 0;

	_syntonize = syntonize;
	_new_syntonization_set_point = false;
	_ppm = 0;

	_master_local_freq_offset_init = false;
	_local_system_freq_offset_init = false;
	_timestamper = timestamper;

	this->ipc = ipc;

 	memset( &LastEBestIdentity, 0xFF, sizeof( LastEBestIdentity ));
	return;
}

bool IEEE1588Clock::serializeState( void *buf, off_t *count ) {
  bool ret = true;
  
  if( buf == NULL ) {
    *count = sizeof( _master_local_freq_offset ) + sizeof( _local_system_freq_offset ) + sizeof( LastEBestIdentity );
    return true;
  }
  
  // Master-Local Frequency Offset
  if( ret && *count >= (off_t) sizeof( _master_local_freq_offset )) {
	  memcpy
		  ( buf, &_master_local_freq_offset,
			sizeof( _master_local_freq_offset ));
	  *count -= sizeof( _master_local_freq_offset );
	  buf = ((char *)buf) + sizeof( _master_local_freq_offset );
  } else if( ret == false ) {
	  *count += sizeof( _master_local_freq_offset );
  } else {
	  *count = sizeof( _master_local_freq_offset )-*count;
	  ret = false;
  }
  
  // Local-System Frequency Offset
  if( ret && *count >= (off_t) sizeof( _local_system_freq_offset )) {
	  memcpy
		  ( buf, &_local_system_freq_offset,(off_t)
			sizeof( _local_system_freq_offset ));
	  *count -= sizeof( _local_system_freq_offset );
	  buf = ((char *)buf) + sizeof( _local_system_freq_offset );
  } else if( ret == false ) {
	  *count += sizeof( _local_system_freq_offset );
  } else {
	  *count = sizeof( _local_system_freq_offset )-*count;
	  ret = false;
  }

  // LastEBestIdentity
  if( ret && *count >= (off_t) sizeof( LastEBestIdentity )) {
    memcpy( buf, &LastEBestIdentity, (off_t) sizeof( LastEBestIdentity ));
    *count -= sizeof( LastEBestIdentity );
    buf = ((char *)buf) + sizeof( LastEBestIdentity );
  } else if( ret == false ) {
    *count += sizeof( LastEBestIdentity );
  } else {
    *count = sizeof( LastEBestIdentity )-*count;
    ret = false;
  }

  return ret;
}

bool IEEE1588Clock::restoreSerializedState( void *buf, off_t *count ) {
	bool ret = true;
  
	/* Master-Local Frequency Offset */
	if( ret && *count >= (off_t) sizeof( _master_local_freq_offset )) {
		memcpy
			( &_master_local_freq_offset, buf, 
			  sizeof( _master_local_freq_offset ));
		*count -= sizeof( _master_local_freq_offset );
		buf = ((char *)buf) + sizeof( _master_local_freq_offset );
	} else if( ret == false ) {
		*count += sizeof( _master_local_freq_offset );
	} else {
		*count = sizeof( _master_local_freq_offset )-*count;
		ret = false;
	}
	
	/* Local-System Frequency Offset */
	if( ret && *count >= (off_t) sizeof( _local_system_freq_offset )) {
		memcpy
			( &_local_system_freq_offset, buf,
			  sizeof( _local_system_freq_offset ));
		*count -= sizeof( _local_system_freq_offset );
		buf = ((char *)buf) + sizeof( _local_system_freq_offset );
	} else if( ret == false ) {
		*count += sizeof( _local_system_freq_offset );
	} else {
		*count = sizeof( _local_system_freq_offset )-*count;
		ret = false;
	}

	/* LastEBestIdentity */
  if( ret && *count >= (off_t) sizeof( LastEBestIdentity )) {
	  memcpy( &LastEBestIdentity, buf, sizeof( LastEBestIdentity ));
	  *count -= sizeof( LastEBestIdentity );
	  buf = ((char *)buf) + sizeof( LastEBestIdentity );
  } else if( ret == false ) {
	  *count += sizeof( LastEBestIdentity );
  } else {
	  *count = sizeof( LastEBestIdentity )-*count;
	  ret = false;
  }

  return ret;
}

Timestamp IEEE1588Clock::getSystemTime(void)
{
	return (Timestamp(0, 0, 0));
}

void timerq_handler(void *arg)
{

	event_descriptor_t *event_descriptor = (event_descriptor_t *) arg;
	event_descriptor->port->processEvent(event_descriptor->event);
}

void IEEE1588Clock::addEventTimer(IEEE1588Port * target, Event e,
				  unsigned long long time_ns)
{
#ifdef MICREL_1588_PTP
	int index = target->getIndex();
	int port_event = e;

	port_event += index * 0x20;
#endif
	event_descriptor_t *event_descriptor = new event_descriptor_t();
	event_descriptor->event = e;
	event_descriptor->port = target;
	timerq->addEvent
#ifdef MICREL_1588_PTP
		((unsigned)(time_ns / 1000), port_event, timerq_handler, event_descriptor,
#else
		((unsigned)(time_ns / 1000), (int)e, timerq_handler, event_descriptor,
#endif
		 true, NULL);
}

void IEEE1588Clock::deleteEventTimer(IEEE1588Port * target, Event event)
{
#ifdef MICREL_1588_PTP
	int index = target->getIndex();
	int port_event = event;

	port_event += index * 0x20;
	timerq->cancelEvent(port_event, NULL);
#else
	timerq->cancelEvent((int)event, NULL);
#endif
}

FrequencyRatio IEEE1588Clock::calcLocalSystemClockRateDifference( Timestamp local_time, Timestamp system_time ) {
	unsigned long long inter_system_time;
	unsigned long long inter_local_time;
	FrequencyRatio ppt_offset;

	XPTPD_INFO( "Calculated local to system clock rate difference" );

	if( !_local_system_freq_offset_init ) {
		_prev_system_time = system_time;
		_prev_local_time = local_time;

		_local_system_freq_offset_init = true;

		return 1.0;
	}

	inter_system_time =
		TIMESTAMP_TO_NS(system_time) - TIMESTAMP_TO_NS(_prev_system_time);
	inter_local_time  =
		TIMESTAMP_TO_NS(local_time) -  TIMESTAMP_TO_NS(_prev_local_time);

	if( inter_system_time != 0 ) {
		ppt_offset = ((FrequencyRatio)inter_local_time)/inter_system_time;
	} else {
		ppt_offset = 1.0;
	}
	
	_prev_system_time = system_time;
	_prev_local_time = local_time;

  return ppt_offset;
}

FrequencyRatio IEEE1588Clock::calcMasterLocalClockRateDifference( Timestamp master_time, Timestamp sync_time ) {
	unsigned long long inter_sync_time;
	unsigned long long inter_master_time;
	FrequencyRatio ppt_offset;
	
	XPTPD_INFO( "Calculated master to local clock rate difference" );

	if( !_master_local_freq_offset_init ) {
		_prev_sync_time = sync_time;
		_prev_master_time = master_time;
	
		_master_local_freq_offset_init = true;
	
		return 1.0;
	}

	inter_sync_time =
		TIMESTAMP_TO_NS(sync_time) - TIMESTAMP_TO_NS(_prev_sync_time);
	inter_master_time =
		TIMESTAMP_TO_NS(master_time) -  TIMESTAMP_TO_NS(_prev_master_time);

	if( inter_sync_time != 0 ) {
		ppt_offset = ((FrequencyRatio)inter_master_time)/inter_sync_time;
	} else {
		ppt_offset = 1.0;
	}

	_prev_sync_time = sync_time;
	_prev_master_time = master_time;

	return ppt_offset;
}

#ifdef MICREL_1588_PTP
int dbg_msg;
signed long long master_ns;
static signed long long last_ns;
static signed long long last_offset;
static int dbg_msg_cnt;
static int dbg_last_sec;
#endif

void IEEE1588Clock::setMasterOffset
( int64_t master_local_offset, Timestamp local_time,
  FrequencyRatio master_local_freq_offset, int64_t local_system_offset,
  Timestamp system_time, FrequencyRatio local_system_freq_offset,
  uint32_t nominal_clock_rate, uint32_t local_clock )
{
#ifdef MICREL_1588_PTP
	int sec;
	double ppm;
	static int just_adjust;

	sec = master_ns / 1000000000;
	dbg_msg = 0;

	/* print initial synchronization messages. */
	if (dbg_msg_cnt < 8) {
		++dbg_msg_cnt;
		dbg_msg = 1;
	}

	/* print every second. */
	if (dbg_last_sec != sec) {
		dbg_last_sec = sec;
		dbg_msg = 1;
	}
	if (!verbose)
		dbg_msg = 0;

	/* Only first adjustment has correct drift. */
	if (2 == adjust_cnt)
		ppm = ((master_local_freq_offset - 1.0) * 1000000);
	else
		ppm = 0;
	if (sync_cnt < 2 || ppm > 100.000 || ppm < -100.000) {
		printf(" F:%lf\n", ppm);
		++sync_cnt;
		return;
	}
#endif
	_master_local_freq_offset = master_local_freq_offset;
	_local_system_freq_offset = local_system_freq_offset;

	if( ipc != NULL ) ipc->update
		( master_local_offset, local_system_offset, master_local_freq_offset,
		  local_system_freq_offset, TIMESTAMP_TO_NS(local_time));

	if( _syntonize ) {
#ifdef MICREL_1588_PTP
if (dbg_msg && (adjust_cnt || just_adjust))
printf("offset: %lld %d %d\n", master_local_offset, adjust_cnt, just_adjust);
#endif

#ifdef MICREL_1588_PTP
		/*
		 * The very next receive timestamp is not accurate after
		 * adjustment because of the very fast Sync rate.
		 */
		if (just_adjust) {
			just_adjust = false;
			return;
		}

		/*
		 * There is still some inaccuracy after adjustment.
		 */
		if (abs(master_local_offset) >= 100 && adjust_cnt) {
			_new_syntonization_set_point = true;
		} else
				if (adjust_cnt)
					--adjust_cnt;
#endif
		if( _new_syntonization_set_point ) {
			_new_syntonization_set_point = false;
			if( _timestamper ) {
				/* Make sure that there are no transmit operations
				   in progress */
#ifdef MICREL_1588_PTP
				just_adjust = true;

				/* Only first adjustment has correct drift. */
				if (2 == adjust_cnt)
					_ppm = ((master_local_freq_offset -
						1.0) * 1000000);
				if (adjust_cnt)
					--adjust_cnt;
#endif
#ifdef MICREL_1588_PTP
if (verbose)
printf("phase: %lld %lf\n", master_local_offset, _ppm);
#endif
				getTxLockAll();
				_timestamper->HWTimestamper_adjclockphase
					( -master_local_offset );
				_master_local_freq_offset_init = false;
				putTxLockAll();
				master_local_offset = 0;
			}
		}
		// Adjust for frequency offset
		long double phase_error = (long double) -master_local_offset;

#ifdef MICREL_1588_PTP
		ppm = _ppm;

		ppm += INTEGRAL * phase_error / 1000;
		_ppm = PROPORTIONAL * phase_error / 1000 + ppm;
#else
		_ppm += (float) (INTEGRAL*phase_error +
			 PROPORTIONAL*((master_local_freq_offset-1.0)*1000000));
#endif
		if( _ppm < LOWER_FREQ_LIMIT ) _ppm = LOWER_FREQ_LIMIT;
		if( _ppm > UPPER_FREQ_LIMIT ) _ppm = UPPER_FREQ_LIMIT;
		if( _timestamper ) {
			if( !_timestamper->HWTimestamper_adjclockrate( _ppm )) {
				XPTPD_ERROR( "Failed to adjust clock rate" );
			}
		}
#ifdef MICREL_1588_PTP
		do {
			int drift;

			drift = ((master_local_offset - last_offset) *
				1000000000) / (master_ns - last_ns);
			last_offset = master_local_offset;
			last_ns = master_ns;
			if (dbg_msg)
				printf(" o:%5lld  d:%5d  f:%lf  ppm:%lf %lf\n",
					master_local_offset, drift,
					(double) master_local_freq_offset,
					_ppm, ppm);
		} while (0);
		_ppm = ppm;
#endif
	}
	
	return;
}

/* Get current time from system clock */
Timestamp IEEE1588Clock::getTime(void)
{
	return getSystemTime();
}

/* Get timestamp from hardware */
Timestamp IEEE1588Clock::getPreciseTime(void)
{
	return getSystemTime();
}

bool IEEE1588Clock::isBetterThan(PTPMessageAnnounce * msg)
{
	unsigned char this1[14];
	unsigned char that1[14];
	uint16_t tmp;

	this1[0] = priority1;
	that1[0] = msg->getGrandmasterPriority1();

	this1[1] = clock_quality.cq_class;
	that1[1] = msg->getGrandmasterClockQuality()->cq_class;

	this1[2] = clock_quality.clockAccuracy;
	that1[2] = msg->getGrandmasterClockQuality()->clockAccuracy;

	tmp = clock_quality.offsetScaledLogVariance;
	tmp = PLAT_htons(tmp);
	memcpy(this1 + 3, &tmp, sizeof(tmp));
	tmp = msg->getGrandmasterClockQuality()->offsetScaledLogVariance;
	tmp = PLAT_htons(tmp);
	memcpy(that1 + 3, &tmp, sizeof(tmp));
	
	this1[5] = priority2;
	that1[5] = msg->getGrandmasterPriority2();
	
	clock_identity.getIdentityString(this1 + 6);
	msg->getGrandmasterIdentity((char *)that1 + 6);

#if 0
	fprintf(stderr, "(Clk)Us: ");
	for (int i = 0; i < 14; ++i)
		fprintf(stderr, "%hhx ", this1[i]);
	fprintf(stderr, "\n");
	fprintf(stderr, "(Clk)Them: ");
	for (int i = 0; i < 14; ++i)
		fprintf(stderr, "%hhx ", that1[i]);
	fprintf(stderr, "\n");
#endif

	return (memcmp(this1, that1, 14) < 0) ? true : false;
}

IEEE1588Clock::~IEEE1588Clock(void)
{
	// Do nothing
}
