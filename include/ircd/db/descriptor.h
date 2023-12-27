// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#pragma once
#define HAVE_IRCD_DB_DATABASE_DESCRIPTOR_H

namespace ircd::db
{
	struct descriptor;
	using description = std::vector<descriptor>;
}

/// Descriptor of a column when opening database. Database must be opened with
/// a consistent set of descriptors describing what will be found upon opening.
struct ircd::db::descriptor
{
	using typing = std::pair<std::type_index, std::type_index>;

	/// User given name for this column. Must be consistent.
	std::string name;

	/// User given description of this column; not used by RocksDB
	std::string explain;

	/// Indicate key and value type.
	typing type { typeid(string_view), typeid(string_view) };

	/// RocksDB ColumnFamilyOptions string; can be used for items not
	/// otherwise specified here.
	std::string options {};

	/// User given comparator. We can automatically set this value for
	/// some types given for the type.first typeid; otherwise it must be
	/// set for exotic/unsupported keys.
	db::comparator cmp {};

	/// User given prefix extractor.
	db::prefix_transform prefix {};

	/// Indicates if this column should be marked for deletion. Users who
	/// upgrade to the new schema will still require a legacy descriptor
	/// with most of the essential fields preceding this value to open db.
	///
	/// !!! Setting this to true deletes all data for this column !!!
	bool drop { false };

	/// Size of the LRU cache for uncompressed blocks
	ssize_t cache_size { -1 };

	/// Bloom filter bits. Filter is still useful even if queries are expected
	/// to always hit on this column; see `expect_queries_hit` option.
	size_t bloom_bits { 0 };

	/// Set this option to true if queries to this column are expected to
	/// find keys that exist. This is useful for columns with keys that
	/// were first found from values in another column, where if the first
	/// column missed there'd be no reason to query this column.
	bool expect_queries_hit { false };

	/// Data block size for uncompressed data. Compression will make the
	/// block smaller when it IO's to and from disk. Smaller blocks may be
	/// more space and query overhead if values exceed this size. Larger
	/// blocks will read and cache unrelated data if values are smaller
	/// than this size.
	size_t block_size { 512 };

	/// Data block size for metadata blocks. Other configuration which may
	/// not yet be in this descriptor affects the best choice of this param;
	/// generally these blocks are preloaded on DB open. They can also
	/// participate in the block cache. At the time this comment was written
	/// top-level metadata blocks are preloaded and leaf blocks are put in
	/// the cache.
	size_t meta_block_size { 512 };

	/// Compression algorithm for this column. Empty string is equal to
	/// kNoCompression. List is semicolon separated to allow fallbacks in
	/// case the first algorithms are not supported. "default" will be
	/// replaced by the string in the ircd.db.compression.default conf item.
	std::string compression {"default"};

	/// User given compaction callback surface.
	db::compactor compactor {};

	/// Compaction priority algorithm
	std::string compaction_pri {};

	/// Compaction related parameters. see: rocksdb/advanced_options.h
	struct
	{
		size_t base {8_MiB - 256_KiB};
		size_t multiplier {2};
	}
	target_file_size;

	/// Compaction related parameters. see: rocksdb/advanced_options.h
	struct max_bytes_for_level
	{
		size_t base {0};
		size_t multiplier {1};
	}
	max_bytes_for_level[8]
	{
		{  32_MiB,   1L }, // max_bytes_for_level_base
		{      0L,   0L }, // max_bytes_for_level[0]
		{      0L,   1L }, // max_bytes_for_level[1]
		{      0L,   1L }, // max_bytes_for_level[2]
		{      0L,   3L }, // max_bytes_for_level[3]
		{      0L,   7L }, // max_bytes_for_level[4]
		{      0L,  15L }, // max_bytes_for_level[5]
		{      0L,  31L }, // max_bytes_for_level[6]
	};

	/// Forces compaction within a certain limit of time
	seconds compaction_period
	{
		60s * 60 * 24 * 21 // 21 day period
	};

	/// The size of a write buffer is `block_size * write_buffer_blocks`
	size_t write_buffer_blocks {8192};

	/// The number of blocks to prefetch on iteration. This should be zero
	/// when the column is only used for point queries. Override on a per-
	/// iteration basis with db::gopts::readahead. Unlike the former, this
	/// value is only a maximum; actual prefetch is decided internally based
	/// on query pattern.
	size_t readahead_blocks {4096};

	/// The number of level0 files allowed to buffer before compacting. Too
	/// much data at level0 will slow down queries, but too much compaction
	/// will increase IOPS for the server with constant reorganization.
	size_t compaction_trigger {2};

	/// Circuit-breaker to disable automatic compaction specifically for this
	/// column from this descriptor.
	bool compaction {true};

	/// Determines whether data in the write_buffer is moved into the cache or
	/// dropped once the buffer is written (flushed).
	bool cache_writes {false};
};
