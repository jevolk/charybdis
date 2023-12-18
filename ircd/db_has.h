// The Construct
//
// Copyright (C) The Construct Developers, Authors & Contributors
// Copyright (C) 2016-2020 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#if ROCKSDB_MAJOR > 5 \
|| (ROCKSDB_MAJOR == 5 && ROCKSDB_MINOR >= 18)
	#define IRCD_DB_HAS_ALLOCATOR 1
#endif

#if ROCKSDB_MAJOR > 5 \
|| (ROCKSDB_MAJOR == 5 && ROCKSDB_MINOR > 18) \
|| (ROCKSDB_MAJOR == 5 && ROCKSDB_MINOR == 18 && ROCKSDB_PATCH >= 3)
	#define IRCD_DB_HAS_ON_COMPACTION_BEGIN 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 1) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 1 && ROCKSDB_PATCH >= 1)
	#define IRCD_DB_HAS_ENV_PRIO_USER 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 1) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 1 && ROCKSDB_PATCH >= 1)
	#define IRCD_DB_HAS_SECONDARY 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 1) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 1 && ROCKSDB_PATCH >= 1)
	#define IRCD_DB_HAS_AVOID_BLOCKING_IO 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 2) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 2 && ROCKSDB_PATCH >= 2)
	#define IRCD_DB_HAS_PERIODIC_COMPACTIONS 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 2) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 2 && ROCKSDB_PATCH >= 2)
	#define IRCD_DB_HAS_MULTIGET_SINGLE 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 3) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 3 && ROCKSDB_PATCH >= 6)
	#define IRCD_DB_HAS_ENV_MULTIREAD 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 3) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 3 && ROCKSDB_PATCH >= 6)
	#define IRCD_DB_HAS_CF_DROPPED 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 3) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 3 && ROCKSDB_PATCH >= 6)
	#define IRCD_DB_HAS_TIMESTAMP 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 4) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 4 && ROCKSDB_PATCH >= 6)
	#define IRCD_DB_HAS_CACHE_GETCHARGE 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 6) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 6 && ROCKSDB_PATCH >= 3)
	#define IRCD_DB_HAS_MULTIGET_BATCHED 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 7) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 7 && ROCKSDB_PATCH >= 3)
	#define IRCD_DB_HAS_ENV_FILESYSTEM 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 8) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 8 && ROCKSDB_PATCH >= 1)
	#define IRCD_DB_HAS_SKIP_CHECKSIZE 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 10) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 10 && ROCKSDB_PATCH >= 0)
	#define IRCD_DB_HAS_MULTIGET_DIRECT 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 10) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 10 && ROCKSDB_PATCH >= 1)
	#define IRCD_DB_HAS_CONFIG_OPTIONS 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 12) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 12 && ROCKSDB_PATCH >= 6)
	#define IRCD_DB_HAS_MULTIREAD_FIX 1
	#define IRCD_DB_HAS_MANIFEST_WRITE 1
	#define IRCD_DB_HAS_LISTENER_FILEIO 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 14) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 14 && ROCKSDB_PATCH >= 5)
	#define IRCD_DB_HAS_FLUSH_RETRY 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 15) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 15 && ROCKSDB_PATCH >= 2)
	#define IRCD_DB_HAS_MANIFEST_WALS 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 15) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 15 && ROCKSDB_PATCH >= 2)
	#define IRCD_DB_HAS_CACHE_META_OPTS 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 19) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 19 && ROCKSDB_PATCH >= 3)
	#define IRCD_DB_HAS_VERSION_ABI 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 20) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 20 && ROCKSDB_PATCH >= 3)
	#define IRCD_DB_HAS_WAL_FULL 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 22) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 22 && ROCKSDB_PATCH >= 1)
	#define IRCD_DB_HAS_CACHE_GETDELETER 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 22) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 22 && ROCKSDB_PATCH >= 1)
	#define IRCD_DB_HAS_CACHE_APPLYTOALL 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 22) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 22 && ROCKSDB_PATCH >= 1)
	#define IRCD_DB_HAS_CACHE_PREPOPULATE 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 24) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 24 && ROCKSDB_PATCH >= 2)
	#define IRCD_DB_HAS_CHANGE_TEMPERATURE 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 25) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 25 && ROCKSDB_PATCH >= 1)
	#define IRCD_DB_HAS_IO_MID 1
	#define IRCD_DB_HAS_IO_USER 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 26) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 26 && ROCKSDB_PATCH >= 0)
	#define IRCD_DB_HAS_FORCED_BLOBGC 1
#endif

#if ROCKSDB_MAJOR > 6 \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR > 28) \
|| (ROCKSDB_MAJOR == 6 && ROCKSDB_MINOR == 28 && ROCKSDB_PATCH >= 2)
	#define IRCD_DB_HAS_LISTENER_RECOVERY 1
#endif

#if ROCKSDB_MAJOR > 7 \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR > 0) \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR == 0 && ROCKSDB_PATCH >= 1)
	#define IRCD_DB_HAS_ON_SUBCOMPACTION 1
#endif

#if ROCKSDB_MAJOR > 7 \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR > 2) \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR == 2 && ROCKSDB_PATCH >= 0)
	#define IRCD_DB_HAS_SECONDARY_CACHE 1
#endif

#if ROCKSDB_MAJOR > 7 \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR > 7) \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR == 7 && ROCKSDB_PATCH >= 2)
	#define IRCD_DB_HAS_MANIFEST_UUIDS 1
#endif

#if ROCKSDB_MAJOR > 7 \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR > 7) \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR == 7 && ROCKSDB_PATCH >= 2)
	#define IRCD_DB_HAS_AUTO_READAHEAD 1
#endif

#if ROCKSDB_MAJOR > 7 \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR > 8) \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR == 8 && ROCKSDB_PATCH >= 3)
	#define IRCD_DB_HAS_ROUND_ROBIN_TTL 1
#endif

#if ROCKSDB_MAJOR > 7 \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR > 10) \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR == 10 && ROCKSDB_PATCH >= 0)
	#define IRCD_DB_HAS_CACHE_ITEMHELPER 1
#endif

#if ROCKSDB_MAJOR > 7 \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR > 10) \
|| (ROCKSDB_MAJOR == 7 && ROCKSDB_MINOR == 10 && ROCKSDB_PATCH >= 2)
	#define IRCD_DB_HAS_REFIT_LEVEL 1
#endif

#if ROCKSDB_MAJOR > 8 \
|| (ROCKSDB_MAJOR == 8 && ROCKSDB_MINOR > 0) \
|| (ROCKSDB_MAJOR == 8 && ROCKSDB_MINOR == 0 && ROCKSDB_PATCH >= 0)
	#define IRCD_DB_HAS_CACHE_WRAPPER 1
#endif

#if ROCKSDB_MAJOR > 8 \
|| (ROCKSDB_MAJOR == 8 && ROCKSDB_MINOR > 1) \
|| (ROCKSDB_MAJOR == 8 && ROCKSDB_MINOR == 1 && ROCKSDB_PATCH >= 1)
	#define IRCD_DB_HAS_CACHE_ASYNC 1
#endif

#if ROCKSDB_MAJOR > 8 \
|| (ROCKSDB_MAJOR == 8 && ROCKSDB_MINOR > 4) \
|| (ROCKSDB_MAJOR == 8 && ROCKSDB_MINOR == 4 && ROCKSDB_PATCH >= 4)
	#define IRCD_DB_HAS_WAIT_FOR_COMPACT 1
#endif
