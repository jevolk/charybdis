// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#include "db.h"

decltype(ircd::db::database::env::log)
ircd::db::database::env::log
{
	"db.env"
};

//
// env::env
//

ircd::db::database::env::env(database *const &d)
:d
{
	*d
}
,st
{
	std::make_unique<state>(d)
}
{
	#ifdef IRCD_DB_HAS_ENV_SYSTEM_CLOCK
	//NOTE: rocksdb::Env constructor is broken; we assign system_clock here.
	this->rocksdb::Env::system_clock_ = std::make_shared<system_clock>(d);
	#endif
}

ircd::db::database::env::~env()
noexcept
{
}

rocksdb::Status
ircd::db::database::env::NewSequentialFile(const std::string &name,
                                           std::unique_ptr<SequentialFile> *const r,
                                           const EnvOptions &options)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] new sequential file '%s' options:%p [mm:%b direct:%b]",
			d.name,
			name,
			&options,
			options.use_mmap_reads,
			options.use_direct_reads,
		};

	*r = std::make_unique<sequential_file>(&d, name, options);
	return Status::OK();
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::NewRandomAccessFile(const std::string &name,
                                             std::unique_ptr<RandomAccessFile> *const r,
                                             const EnvOptions &options)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] new random access file '%s' options:%p [mm:%b direct:%b bufsz:%zu readahead:%zu]",
			d.name,
			name,
			&options,
			options.use_mmap_reads,
			options.use_direct_reads,
			options.random_access_max_buffer_size,
			options.compaction_readahead_size,
		};

	*r = std::make_unique<random_access_file>(&d, name, options);
	return Status::OK();
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::NewWritableFile(const std::string &name,
                                         std::unique_ptr<WritableFile> *const r,
                                         const EnvOptions &options)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] new writable file '%s' options:%p [mm:%b direct:%b rl:%p bufsz:%zu syncsz:%zu]",
			d.name,
			name,
			&options,
			options.use_mmap_writes,
			options.use_direct_writes,
			options.rate_limiter,
			options.writable_file_max_buffer_size,
			options.bytes_per_sync,
		};

	if(options.use_direct_writes)
		*r = std::make_unique<writable_file_direct>(&d, name, options, true, false);
	else
		*r = std::make_unique<writable_file>(&d, name, options, true, false);

	return Status::OK();
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::ReopenWritableFile(const std::string &name,
                                            std::unique_ptr<WritableFile> *const r,
                                            const EnvOptions &options)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] reopen writable file '%s' options:%p",
			d.name,
			name,
			&options
		};

	if(options.use_direct_writes)
		*r = std::make_unique<writable_file_direct>(&d, name, options, false, true);
	else
		*r = std::make_unique<writable_file>(&d, name, options, false, true);

	return Status::OK();
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
__attribute__((unused))
ircd::db::database::env::ReuseWritableFile(const std::string &name,
                                           const std::string &old_name,
                                           std::unique_ptr<WritableFile> *const r,
                                           const EnvOptions &options)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] reuse writable file '%s' old '%s' options:%p",
			d.name,
			name,
			old_name,
			&options
		};

	throw ircd::not_implemented
	{
		"[%s] ReuseWritableFile(name:'%s' old:'%s')",
		d.name,
		name,
		old_name
	};

	return Status::OK();
	//return defaults.ReuseWritableFile(name, old_name, r, options);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::NewRandomRWFile(const std::string &name,
                                         std::unique_ptr<RandomRWFile> *const result,
                                         const EnvOptions &options)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] new random read/write file '%s' options:%p",
			d.name,
			name,
			&options
		};

	*result = std::make_unique<random_rw_file>(&d, name, options);
	return Status::OK();
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::NewDirectory(const std::string &name,
                                      std::unique_ptr<Directory> *const result)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] new directory '%s'",
			d.name,
			name
		};

	std::unique_ptr<Directory> defaults;
	const auto ret
	{
		this->defaults.NewDirectory(name, &defaults)
	};

	*result = std::make_unique<directory>(&d, name, std::move(defaults));
	return ret;
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::FileExists(const std::string &f)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] file exists '%s'",
			d.name,
			f
		};

	return defaults.FileExists(f);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::GetChildren(const std::string &dir,
                                     std::vector<std::string> *const r)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] get children of directory '%s'",
			d.name,
			dir
		};

	return defaults.GetChildren(dir, r);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::GetChildrenFileAttributes(const std::string &dir,
                                                   std::vector<FileAttributes> *const result)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] get children file attributes of directory '%s'",
			d.name,
			dir
		};

	return defaults.GetChildrenFileAttributes(dir, result);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::DeleteFile(const std::string &name)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] delete file '%s'",
			d.name,
			name
		};

	return defaults.DeleteFile(name);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::CreateDir(const std::string &name)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] create directory '%s'",
			d.name,
			name
		};

	return defaults.CreateDir(name);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::CreateDirIfMissing(const std::string &name)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] create directory if missing '%s'",
			d.name,
			name
		};

	return defaults.CreateDirIfMissing(name);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::DeleteDir(const std::string &name)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] delete directory '%s'",
			d.name,
			name
		};

	return defaults.DeleteDir(name);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::GetFileSize(const std::string &name,
                                     uint64_t *const s)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] get file size '%s'",
			d.name,
			name
		};

	assert(s);
	*s = fs::size(name);
	return Status::OK();
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::GetFileModificationTime(const std::string &name,
                                                 uint64_t *const file_mtime)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] get file mtime '%s'",
			d.name,
			name
		};

	return defaults.GetFileModificationTime(name, file_mtime);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::RenameFile(const std::string &s,
                                    const std::string &t)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] rename file '%s' to '%s'",
			d.name,
			s,
			t
		};

	return defaults.RenameFile(s, t);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::LinkFile(const std::string &s,
                                  const std::string &t)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] link file '%s' to '%s'",
			d.name,
			s,
			t
		};

	return defaults.LinkFile(s, t);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::LockFile(const std::string &name,
                                  FileLock** l)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] lock file '%s'",
			d.name,
			name
		};

	return defaults.LockFile(name, l);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::UnlockFile(FileLock *const l)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] unlock file lock:%p",
			d.name,
			l
		};

	return defaults.UnlockFile(l);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::GetTestDirectory(std::string *const path)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	return defaults.GetTestDirectory(path);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::GetAbsolutePath(const std::string &db_path,
                                         std::string *const output_path)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] get absolute path from '%s' ret:%p",
			d.name,
			db_path,
			output_path
		};

	return defaults.GetAbsolutePath(db_path, output_path);
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::NewLogger(const std::string &name,
                                   std::shared_ptr<Logger> *const result)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] new logger '%s' result:%p",
			d.name,
			name,
			(const void *)result
		};

	return defaults.NewLogger(name, result);
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::GetHostName(char *const name,
                                     uint64_t len)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] get host name name:%p len:%lu",
			d.name,
			name,
			len
		};

	return defaults.GetHostName(name, len);
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

[[gnu::hot]]
uint64_t
ircd::db::database::env::NowMicros()
noexcept
{
	return ircd::time<microseconds>();
}

/// Bug in rocksdb causes this to not be called all the time, specifically
/// for perf events.
[[gnu::hot]]
uint64_t
ircd::db::database::env::NowNanos()
noexcept
{
	return ircd::now<nanoseconds>().count();
}

[[gnu::hot]]
uint64_t
ircd::db::database::env::NowCPUNanos()
noexcept
{
	return ircd::prof::cycles();
}

rocksdb::Status
ircd::db::database::env::GetCurrentTime(int64_t *const unix_time)
noexcept try
{
	ircd::time(unix_time);
	return Status::OK();
}
catch(const std::exception &e)
{
	return error_to_status{e};
}

std::string
ircd::db::database::env::TimeToString(uint64_t time)
noexcept try
{
	return defaults.TimeToString(time);
}
catch(const std::exception &e)
{
	ircd::terminate
	{
		"[%s] time to string :%s",
		d.name,
		e.what()
	};
}

void
ircd::db::database::env::SleepForMicroseconds(int micros)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			"[%s] sleep for %d microseconds",
			d.name,
			micros
		};

	ctx::sleep(microseconds(micros));
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] sleep micros:%d :%s",
		d.name,
		micros,
		e.what()
	};
}

void
ircd::db::database::env::Schedule(void (*f)(void* arg),
                                  void *const a,
                                  Priority prio,
                                  void *const tag,
                                  void (*u)(void* arg))
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV || (true))
		log::debug
		{
			log, "[%s] schedule func:%p a:%p tag:%p u:%p prio:%s",
			d.name,
			f,
			a,
			tag,
			u,
			reflect(prio)
		};

	assert(st);
	auto &pool
	{
		*st->pool.at(prio)
	};

	pool(state::task
	{
		f, u, a
	});
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] schedule func:%p a:%p tag:%p u:%p prio:%s",
		d.name,
		f,
		a,
		tag,
		u,
		reflect(prio)
	};
}

int
ircd::db::database::env::UnSchedule(void *const tag,
                                    const Priority prio)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV || (true))
		log::debug
		{
			log, "[%s] unschedule tag:%p prio:%s",
			d.name,
			tag,
			reflect(prio)
		};

	assert(st);
	auto &pool
	{
		*st->pool.at(prio)
	};

	return pool.cancel(tag);
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] unschedule tag:%p prio:%s :%s",
		d.name,
		tag,
		reflect(prio),
		e.what()
	};

	return 0;
}

void
ircd::db::database::env::StartThread(void (*f)(void*),
                                     void *const a)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV || (true))
		log::debug
		{
			log, "[%s] start thread func:%p a:%p",
			d.name,
			f,
			a
		};

	throw ircd::not_implemented
	{
		"Independent (non-pool) context spawning not yet implemented"
	};
}
catch(const std::exception &e)
{
	ircd::terminate
	{
		"[%s] start thread :%s",
		d.name,
		e.what()
	};
}

void
ircd::db::database::env::WaitForJoin()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] wait for all ctx to join",
			d.name
		};

	assert(st);
	for(auto &pool : st->pool)
		if(pool)
			pool->join();
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] wait for join :%s",
		d.name,
		e.what()
	};
}

unsigned int
ircd::db::database::env::GetThreadPoolQueueLen(Priority prio)
const noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] get thread pool queue len prio:%s",
			d.name,
			reflect(prio)
		};

	assert(st);
	const auto &pool
	{
		*st->pool.at(prio)
	};

	return pool.tasks.size();
}
catch(const std::exception &e)
{
	ircd::terminate
	{
		"[%s] set background threads :%s",
		d.name,
		e.what()
	};
}

void
ircd::db::database::env::SetBackgroundThreads(int num,
                                              Priority prio)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] set background threads prio:%s num:%d",
			d.name,
			reflect(prio),
			num
		};

	assert(st);
	auto &pool
	{
		*st->pool.at(prio)
	};

	assert(num > 0);
	pool.popts.limit = num;
	pool.popts.dynamic = false;
	pool.p.set(num);
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] set background threads prio:%s num:%d :%s",
		d.name,
		reflect(prio),
		num,
		e.what()
	};
}

void
ircd::db::database::env::IncBackgroundThreadsIfNeeded(int num,
                                                      Priority prio)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] increase background threads num:%d prio:%s",
			d.name,
			num,
			reflect(prio)
		};

	assert(st);
	auto &pool
	{
		*st->pool.at(prio)
	};

	assert(num > 0);
	pool.popts.limit = num;
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] inc background threads num:%d prio:%s :%s",
		d.name,
		num,
		reflect(prio),
		e.what()
	};
}

void
ircd::db::database::env::LowerThreadPoolIOPriority(Priority prio)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] lower thread pool priority prio:%s",
			d.name,
			reflect(prio)
		};

	assert(st);
	auto &pool
	{
		*st->pool.at(prio)
	};

	switch(pool.iopri)
	{
		case IOPriority::IO_HIGH:
			pool.iopri = IOPriority::IO_LOW;
			break;

		default:
			break;
	}
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] lower thread pool IO priority pool:%s :%s",
		d.name,
		reflect(prio),
		e.what()
	};
}

rocksdb::Status
ircd::db::database::env::GetThreadList(std::vector<ThreadStatus> *const list)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] get thread list %p (%zu)",
			d.name,
			list,
			list? list->size() : 0UL
		};

	throw ircd::not_implemented
	{
		"[%s] GetThreadList()", d.name
	};

	return defaults.GetThreadList(list);
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] get thread list:%p :%s",
		d.name,
		list,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::ThreadStatusUpdater *
ircd::db::database::env::GetThreadStatusUpdater()
const noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] get thread status updater",
			d.name,
		};

	return defaults.GetThreadStatusUpdater();
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] get thread status updater :%s",
		d.name,
		e.what()
	};

	return nullptr;
}


uint64_t
ircd::db::database::env::GetThreadID()
const noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] get thread ID",
			d.name,
		};

	return ctx::this_ctx::id();
}
catch(const std::exception &e)
{
	ircd::terminate
	{
		"[%s] get thread id :%s",
		d.name,
		e.what()
	};
}

int
ircd::db::database::env::GetBackgroundThreads(Priority prio)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] get background threads prio:%s",
			d.name,
			reflect(prio)
		};

	assert(st);
	const auto &pool
	{
		*st->pool.at(prio)
	};

	return pool.p.size();
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] get background threads prio:%s :%s",
		d.name,
		reflect(prio),
		e.what()
	};

	return 0;
}

#ifdef IRCD_DB_HAS_ENV_RESERVE_THREADS
int
ircd::db::database::env::ReserveThreads(int num,
                                        Priority prio)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] reserve threads num:%d prio:%s",
			d.name,
			num,
			reflect(prio),
		};

	assert(st);
	return 0;
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] reserve threads :%s",
		d.name,
		e.what()
	};

	return 0;
}
#endif

#ifdef IRCD_DB_HAS_ENV_RESERVE_THREADS
int
ircd::db::database::env::ReleaseThreads(int num,
                                        Priority prio)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] release threads num:%d prio:%s",
			d.name,
			num,
			reflect(prio),
		};

	assert(st);
	return 0;
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] release threads :%s",
		d.name,
		e.what()
	};

	return 0;
}
#endif

rocksdb::Env::Priority
ircd::db::database::env::make_prio(const IOPriority prio)
noexcept
{
	return unmake_nice(make_nice(prio));
}

rocksdb::Env::IOPriority
ircd::db::database::env::make_ioprio(const Priority prio)
noexcept
{
	return unmake_ionice(make_nice(prio));
}

rocksdb::Env::Priority
ircd::db::database::env::unmake_nice(const int8_t nice)
noexcept
{
	if(nice >= make_nice(Priority::BOTTOM))
		return Priority::BOTTOM;

	if(nice >= make_nice(Priority::LOW))
		return Priority::LOW;

	if(nice >= make_nice(Priority::HIGH))
		return Priority::HIGH;

	#ifdef IRCD_DB_HAS_ENV_PRIO_USER
	return Priority::USER;
	#else
	return Priority::HIGH;
	#endif
}

rocksdb::Env::IOPriority
ircd::db::database::env::unmake_ionice(const int8_t nice)
noexcept
{
	if(nice >= make_nice(IOPriority::IO_LOW))
		return IOPriority::IO_LOW;

	#ifdef IRCD_DB_HAS_IO_MID
	if(nice >= make_nice(IOPriority::IO_MID))
		return IOPriority::IO_MID;
	#endif

	if(nice >= make_nice(IOPriority::IO_HIGH))
		return IOPriority::IO_HIGH;

	#ifdef IRCD_DB_HAS_IO_USER
	return IOPriority::IO_USER;
	#else
	return IOPriority::IO_HIGH;
	#endif
}

int8_t
ircd::db::database::env::make_nice(const Priority prio)
noexcept
{
	switch(prio)
	{
		case Priority::BOTTOM:   return 20;
		case Priority::LOW:      return 10;
		case Priority::HIGH:     return 5;
		#ifdef IRCD_DB_HAS_ENV_PRIO_USER
		case Priority::USER:     return 0;
		#endif

		case Priority::TOTAL:    assert(0);
	}

	return 0;
}

int8_t
ircd::db::database::env::make_nice(const IOPriority prio)
noexcept
{
	switch(prio)
	{
		case IOPriority::IO_LOW:    return 20;
		#ifdef IRCD_DB_HAS_IO_MID
		case IOPriority::IO_MID:    return 10;
		#endif
		case IOPriority::IO_HIGH:   return 5;
		#ifdef IRCD_DB_HAS_IO_USER
		case IOPriority::IO_USER:   return 0;
		#endif

		case IOPriority::IO_TOTAL:  assert(0);
	}

	return 0;
}

//
// system_clock
//
#ifdef IRCD_DB_HAS_ENV_SYSTEM_CLOCK

ircd::db::database::env::system_clock::system_clock(database *const &d)
:d{*d}
{
}

ircd::db::database::env::system_clock::~system_clock()
noexcept
{
}

uint64_t
ircd::db::database::env::system_clock::NowMicros()
noexcept
{
	return ircd::time<microseconds>();
}

uint64_t
ircd::db::database::env::system_clock::NowNanos()
noexcept
{
	return ircd::now<nanoseconds>().count();
}

uint64_t
ircd::db::database::env::system_clock::CPUMicros()
noexcept
{
	return ctx::this_ctx::cycles() / 1000;
}

uint64_t
ircd::db::database::env::system_clock::CPUNanos()
noexcept
{
	return ctx::this_ctx::cycles();
}

void
ircd::db::database::env::system_clock::SleepForMicroseconds(int micros)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			"[%s] sleep for %d microseconds",
			d.name,
			micros
		};

	ctx::sleep(microseconds(micros));
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] sleep micros:%d :%s",
		d.name,
		micros,
		e.what()
	};
}

bool
ircd::db::database::env::system_clock::TimedWait(rocksdb::port::CondVar *const cond,
                                                 microseconds deadline)
noexcept
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			"[%s] timed wait cond:%p deadline:%ld",
			d.name,
			cond,
			deadline.count(),
		};

	assert(cond);
	return cond->TimedWait(deadline.count());
}

rocksdb::Status
ircd::db::database::env::system_clock::GetCurrentTime(int64_t *const t)
noexcept
{
	assert(t);
	ircd::time<seconds>(t);
	return Status::OK();
}

std::string
ircd::db::database::env::system_clock::TimeToString(uint64_t t)
noexcept
{
	return Default()->TimeToString(t);
}

const char *
ircd::db::database::env::system_clock::Name()
const noexcept
{
	return db::name(d).c_str();
}

#endif IRCD_DB_HAS_ENV_SYSTEM_CLOCK

//
// writable_file
//

decltype(ircd::db::database::env::writable_file::internal_filesize)
ircd::db::database::env::writable_file::internal_filesize
{
	{ "name",     "ircd.db.env.writable_file.internal_filesize" },
	{ "default",  true                                          },
};

ircd::db::database::env::writable_file::writable_file(database *const &d,
                                                      const std::string &path,
                                                      const EnvOptions &env_opts,
                                                      const bool &trunc,
                                                      const bool &ate)
try
:d
{
	*d
}
,name
{
	fs::filename(_namebuf, path)
}
,env_opts
{
	env_opts
}
,opts
{
	.mode = std::ios::out | (trunc? std::ios::trunc : std::ios::openmode(0)),
	.ate = ate,
	.direct = this->env_opts.use_direct_writes,
	.cloexec = this->env_opts.set_fd_cloexec,
	.dontneed = true,
}
,ionice
{
	ctx::ionice(ctx::cur())
}
,fd
{
	path, this->opts
}
,logical_offset
{
	!trunc?
		fs::size(fd):
		size_t(0)
}
,preallocation_block_size
{
	ircd::info::page_size
}
{
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] opened wfile:%p fd:%d '%s'",
			d->name,
			this,
			int(fd),
			path
		};

	// Workaround a RocksDB bug which doesn't propagate EnvOptions properly
	// on some constructions of WritableFile early on during db open. We'll
	// get an env_opts.allow_fallocate==true here while it should be false
	// from the DBOptions at d->opts. We use &= so it's not set to true when
	// the caller specifically wants it false just for them.
	assert(d && d->opts);
	this->env_opts.allow_fallocate &= d->opts->allow_fallocate;
	//assert(env_opts.allow_fallocate == d->opts->allow_fallocate);
}
catch(const std::exception &e)
{
	log::error
	{
		log, "[%s] opening wfile:%p `%s' :%s",
		d->name,
		this,
		path,
		e.what()
	};
}

ircd::db::database::env::writable_file::~writable_file()
noexcept
{
	Close();

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d closed",
			d.name,
			name,
			int(fd)
		};
}

rocksdb::Status
ircd::db::database::env::writable_file::Close()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if(!fd)
		return Status::OK();

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d close",
			d.name,
			name,
			int(fd)
		};

	if(internal_filesize)
	{
		// Check if our internal state agrees with the real file size.
		const auto final_offset(fs::size(fd));
		if(unlikely(final_offset != this->logical_offset))
			log::critical
			{
				log, "[%s]'%s' fd:%d size check failed; internal:%zu vs. kernel:%zu",
				d.name,
				name,
				int(fd),
				this->logical_offset,
				final_offset,
			};
	}

	fd = fs::fd{};
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' close :%s",
		d.name,
		name,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "[%s]'%s' close :%s",
		d.name,
		name,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file::Flush()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d flush%s",
			d.name,
			name,
			int(fd),
			!db::paranoid_sync?
				" (noop)"_sv:
				string_view{},
		};

	if(db::paranoid_sync)
	{
		fs::sync_opts opts;
		opts.metadata = false;
		opts.priority = ionice;
		opts.nodelay = nodelay;
		fs::sync(fd, opts);
	}

	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d flush :%s",
		d.name,
		name,
		int(fd),
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d flush :%s",
		d.name,
		name,
		int(fd),
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file::Sync()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d sync",
			d.name,
			name,
			int(fd),
		};

	fs::sync_opts opts;
	opts.metadata = true;
	opts.priority = ionice;
	opts.nodelay = nodelay;
	fs::sync(fd, opts);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d sync :%s",
		d.name,
		name,
		int(fd),
		e.what(),
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d sync :%s",
		d.name,
		name,
		int(fd),
		e.what(),
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file::Fsync()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d fsync",
			d.name,
			name,
			int(fd),
		};

	fs::sync_opts opts;
	opts.metadata = bool(paranoid_sync);
	opts.priority = ionice;
	opts.nodelay = nodelay;
	fs::sync(fd, opts);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d fsync :%s",
		d.name,
		name,
		int(fd),
		e.what(),
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d fsync :%s",
		d.name,
		name,
		int(fd),
		e.what(),
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file::RangeSync(uint64_t offset,
                                                  uint64_t length)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			"[%s]'%s' fd:%d range sync offset:%lu length:%lu",
			d.name,
			name,
			int(fd),
			offset,
			length
		};

	// RocksDB sez they want us to initiate flushing of dirty pages
	// asynchronously without waiting for completion. RocksDB allows
	// this callback to be a no-op and do nothing at all.
	//
	// We plug this into a "range flush" gimmick in ircd::fs which almost
	// certainly calls fdatasync() and ignores the range; it may one day
	// on supporting platforms and in certain circumstances call
	// sync_file_range() without any of the wait flags and respect the range.

	fs::sync_opts opts;
	opts.metadata = false;
	opts.priority = ionice;
	opts.nodelay = nodelay;
	fs::sync(fd, offset, length, opts);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d range sync offset:%zu length:%zu :%s",
		d.name,
		name,
		int(fd),
		offset,
		length,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' fd:%d range sync offset:%zu length:%zu :%s",
		d.name,
		name,
		int(fd),
		offset,
		length,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file::Truncate(uint64_t size)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			"[%s]'%s' fd:%d truncate to %lu bytes",
			d.name,
			name,
			int(fd),
			size
		};

	fs::write_opts wopts;
	wopts.priority = ionice;
	wopts.nodelay = nodelay;
	wopts.interruptible = false;
	fs::truncate(fd, size, wopts);
	logical_offset = size;
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d truncate to %lu bytes :%s",
		d.name,
		name,
		int(fd),
		size,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' fd:%d truncate to %lu bytes :%s",
		d.name,
		name,
		int(fd),
		size,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file::InvalidateCache(size_t offset,
                                                        size_t length)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d invalidate cache offset:%zu length:%zu",
			d.name,
			name,
			int(fd),
			offset,
			length
		};

	if(opts.direct)
		return Status::OK();

	fs::evict(fd, length, offset);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d invalidate cache offset:%zu length:%zu",
		d.name,
		name,
		int(fd),
		offset,
		length
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' fd:%d invalidate cache offset:%zu length:%zu",
		d.name,
		name,
		int(fd),
		offset,
		length
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file::Append(const Slice &s)
noexcept try
{
	assert(!opts.direct);
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d append:%p bytes:%zu",
			d.name,
			name,
			int(fd),
			data(s),
			size(s),
		};

	fs::write_opts wopts;
	wopts.priority = ionice;
	wopts.nodelay = nodelay;
	wopts.interruptible = false;
	const const_buffer buf
	{
		data(s), size(s)
	};

	const const_buffer wrote
	{
		fs::append(fd, buf, wopts)
	};

	logical_offset += size(wrote);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d append:%p size:%zu :%s",
		d.name,
		name,
		int(fd),
		data(s),
		size(s),
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' fd:%d append:%p size:%zu :%s",
		d.name,
		name,
		int(fd),
		data(s),
		size(s),
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file::PositionedAppend(const Slice &s,
                                                         uint64_t offset)
noexcept try
{
	assert(!opts.direct);
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			"[%s]'%s' fd:%d append:%p bytes:%zu offset:%lu",
			d.name,
			name,
			int(fd),
			data(s),
			size(s),
			offset
		};

	fs::write_opts wopts;
	wopts.priority = ionice;
	wopts.nodelay = nodelay;
	wopts.offset = offset;
	wopts.interruptible = false;
	const const_buffer buf
	{
		data(s), size(s)
	};

	const const_buffer wrote
	{
		fs::append(fd, buf, wopts)
	};

	logical_offset = std::max(logical_offset, offset + size(wrote));
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d append:%p size:%zu offset:%zu :%s",
		d.name,
		name,
		int(fd),
		data(s),
		size(s),
		offset,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' fd:%d append:%p size:%zu offset:%lu :%s",
		d.name,
		name,
		int(fd),
		data(s),
		size(s),
		offset,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file::Allocate(uint64_t offset,
                                                 uint64_t length)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d allocate offset:%lu length:%lu%s%s",
			d.name,
			name,
			int(fd),
			offset,
			length,
			env_opts.fallocate_with_keep_size? " KEEP_SIZE" : "",
			env_opts.allow_fallocate? "" : " (DISABLED)"
		};

	if(!env_opts.allow_fallocate)
		return Status::NotSupported();

	_allocate(offset, length);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d allocate offset:%zu length:%zu :%s",
		d.name,
		name,
		int(fd),
		offset,
		length,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' fd:%d allocate offset:%zu length:%zu :%s",
		d.name,
		name,
		int(fd),
		offset,
		length,
		e.what()
	};

	return error_to_status{e};
}

void
ircd::db::database::env::writable_file::PrepareWrite(size_t offset,
                                                     size_t length)
noexcept
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' prepare write offset:%zu length:%zu",
			d.name,
			name,
			offset,
			length
		};

	if(!env_opts.allow_fallocate)
		return;

	_allocate(offset, length);
}

void
ircd::db::database::env::writable_file::_allocate(const size_t offset,
                                                  const size_t length)
{
	const size_t first_block
	{
		offset / preallocation_block_size
	};

	const size_t last_block
	{
		(offset + length) / preallocation_block_size
	};

	const ssize_t missing_blocks
	{
		ssize_t(last_block) - preallocation_last_block
	};

	// Fast bail when the offset and length are behind the last block already
	// allocated. We don't support windowing here. If this branch is not taken
	// we'll fallocate() contiguously from the last fallocate() (or offset 0).
	if(missing_blocks <= 0)
		return;

	const ssize_t start_block
	{
		preallocation_last_block + 1
	};

	const size_t allocate_offset
	{
		start_block * preallocation_block_size
	};

	const size_t allocate_length
	{
		missing_blocks * preallocation_block_size
	};

	fs::write_opts wopts;
	wopts.offset = allocate_offset;
	wopts.priority = ionice;
	wopts.nodelay = nodelay;
	wopts.keep_size = env_opts.fallocate_with_keep_size;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d allocating %zd blocks after block:%zu offset:%lu length:%lu%s",
			d.name,
			name,
			int(fd),
			missing_blocks,
			start_block,
			allocate_offset,
			allocate_length,
			wopts.keep_size? " KEEP_SIZE" : ""
		};

	assert(env_opts.allow_fallocate);
	assert(bool(d.opts));
	assert(d.opts->allow_fallocate);

	fs::allocate(fd, allocate_length, wopts);
	this->preallocation_last_block = last_block;
	if(!env_opts.fallocate_with_keep_size)
		this->logical_offset = std::max(this->logical_offset, allocate_offset + allocate_length);
}

void
ircd::db::database::env::writable_file::GetPreallocationStatus(size_t *const block_size,
                                                               size_t *const last_allocated_block)
noexcept
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	*block_size = this->preallocation_block_size;
	*last_allocated_block = this->preallocation_last_block;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' get preallocation block_size(%p):%zu last_block(%p):%zu",
			d.name,
			name,
			block_size,
			*block_size,
			last_allocated_block,
			*last_allocated_block
		};
}

void
ircd::db::database::env::writable_file::SetPreallocationBlockSize(size_t size)
noexcept
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' set preallocation block size:%zu",
			d.name,
			name,
			size
		};

	this->preallocation_block_size = size;
}

uint64_t
ircd::db::database::env::writable_file::GetFileSize()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d get file size; logical:%zu",
			d.name,
			name,
			int(fd),
			logical_offset,
		};

	const auto ret
	{
		!internal_filesize?
			fs::size(fd):
			logical_offset
	};

	assert(logical_offset == ret);
	return ret;
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' fd:%d get file size :%s",
		d.name,
		name,
		int(fd),
		e.what()
	};

	return 0;
}

void
ircd::db::database::env::writable_file::SetIOPriority(Env::IOPriority prio)
noexcept
{
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' IO priority %s",
			d.name,
			name,
			reflect(prio)
		};

	this->prio = prio;
	this->ionice = make_nice(prio);
	switch(this->prio)
	{
		case IOPriority::IO_HIGH:
			nodelay = true;
			break;

		default:
		case IOPriority::IO_LOW:
			nodelay = false;
			break;
	}
}

rocksdb::Env::IOPriority
ircd::db::database::env::writable_file::GetIOPriority()
noexcept
{
	return prio;
}

void
ircd::db::database::env::writable_file::SetWriteLifeTimeHint(WriteLifeTimeHint hint)
noexcept try
{
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' hint:%d %s",
			d.name,
			name,
			int(hint),
			reflect(hint),
		};

	assert(this->hint != hint || hint == WriteLifeTimeHint::WLTH_NOT_SET);
	if(std::exchange(this->hint, hint) == hint)
		return;

	assert(this->hint == hint);
	fs::write_life(fd, this->hint);
}
catch(const std::system_error &e)
{
	log::derror
	{
		log, "[%s]'%s' fd:%d setting write lifetime hint:%d %s :%s",
		d.name,
		name,
		int(fd),
		int(hint),
		reflect(hint),
		e.what(),
	};
}

rocksdb::Env::WriteLifeTimeHint
ircd::db::database::env::writable_file::GetWriteLifeTimeHint()
noexcept
{
	return hint;
}

size_t
ircd::db::database::env::writable_file::GetUniqueId(char *const id,
                                                    size_t max_size)
const noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			"[%s]'%s' get unique id:%p max_size:%zu",
			d.name,
			name,
			id,
			max_size
		};

	const mutable_buffer buf
	{
		id, max_size
	};

	//return size(fs::uuid(fd, buf));
	return 0;
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' get unique id :%s",
		d.name,
		name,
		e.what()
	};

	return 0;
}

bool
ircd::db::database::env::writable_file::IsSyncThreadSafe()
const noexcept try
{
	return true;
}
catch(...)
{
	return false;
}

//
// writable_file_direct
//

ircd::db::database::env::writable_file_direct::writable_file_direct(database *const &d,
                                                                    const std::string &path,
                                                                    const EnvOptions &env_opts,
                                                                    const bool &trunc,
                                                                    const bool &ate)
:writable_file
{
	d, path, env_opts, trunc, ate
}
,alignment
{
	fs::block_size(fd)
}
,buffer
{
	alignment, alignment
}
{
	zero(buffer);
	if(!aligned(logical_offset))
		throw panic
		{
			"direct writable file requires read into buffer."
		};
}

rocksdb::Status
ircd::db::database::env::writable_file_direct::Close()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if(!fd)
		return Status::OK();

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' DIRECT fd:%d close",
			d.name,
			name,
			int(fd)
		};

	if(logical_offset > 0 && fs::size(fd) != logical_offset)
	{
		fs::write_opts wopts;
		wopts.priority = this->ionice;
		wopts.nodelay = true;
		wopts.interruptible = false;
		fs::truncate(fd, logical_offset, wopts);
	}

	fd = fs::fd{};
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' DIRECT close :%s",
		d.name,
		name,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "[%s]'%s' DIRECT close :%s",
		d.name,
		name,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file_direct::Truncate(uint64_t size)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			"[%s]'%s' DIRECT fd:%d truncate to %lu bytes",
			d.name,
			name,
			int(fd),
			size
		};

	fs::write_opts wopts;
	wopts.priority = this->ionice;
	wopts.nodelay = true;
	wopts.interruptible = false;
	fs::truncate(fd, size, wopts);
	logical_offset = size;
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' DIRECT fd:%d truncate to %lu bytes :%s",
		d.name,
		name,
		int(fd),
		size,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' DIRECT fd:%d truncate to %lu bytes :%s",
		d.name,
		name,
		int(fd),
		size,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file_direct::Append(const Slice &s)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if(!aligned(logical_offset) || !aligned(data(s)))
		log::dwarning
		{
			log, "[%s] ALIGNMENT CHECK fd:%d append:%p%s bytes:%zu%s logical_offset:%zu%s",
			d.name,
			int(fd),
			data(s),
			aligned(data(s))? "" : "#AC",
			size(s),
			aligned(size(s))? "" : "#AC",
			logical_offset,
			aligned(logical_offset)? "" : "#AC"
		};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' DIRECT fd:%d append:%p%s bytes:%zu%s logical_offset:%zu%s",
			d.name,
			name,
			int(fd),
			data(s),
			aligned(data(s))? "" : "#AC",
			size(s),
			aligned(size(s))? "" : "#AC",
			logical_offset,
			aligned(logical_offset)? "" : "#AC"
		};

	const auto logical_check
	{
		logical_offset
	};

	const_buffer buf
	{
		slice(s)
	};

	while(!empty(buf))
		buf = write(buf);

	assert(logical_check + size(slice(s)) == logical_offset);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' DIRECT fd:%d append:%p size:%zu :%s",
		d.name,
		name,
		int(fd),
		data(s),
		size(s),
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' DIRECT fd:%d append:%p size:%zu :%s",
		d.name,
		name,
		int(fd),
		data(s),
		size(s),
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::writable_file_direct::PositionedAppend(const Slice &s,
                                                                uint64_t offset)
noexcept
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' DIRECT fd:%d append:%p%s bytes:%zu%s offset:%zu%s",
			d.name,
			name,
			int(fd),
			data(s),
			aligned(data(s))? "" : "#AC",
			size(s),
			aligned(size(s))? "" : "#AC",
			offset,
			aligned(offset)? "" : "#AC"
		};

	return rocksdb::Status::NotSupported();
}

uint64_t
ircd::db::database::env::writable_file_direct::GetFileSize()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock{mutex};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' DIRECT fd:%d get file size",
			d.name,
			name,
			int(fd)
		};

	const auto &ret
	{
		logical_offset
	};

	assert(ret <= fs::size(fd));
	return ret;
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' DIRECT fd:%d get file size :%s",
		d.name,
		name,
		int(fd),
		e.what()
	};

	return 0;
}

/// (Internal) Append buffer. This function is the internal entry interface
/// for appending a buffer of any size and alignment to the file. It is
/// internal because it does no locking or error handling back to rocksdb,
/// because it's expected to be called from some virtual override which does
/// those things. This function will branch off as required to other internal
/// write_* functions to properly align and rebuffer the supplied buffer
/// eventually culminating in an aligned append to the file.
///
/// Calling this function will always result in some write to the file; even
/// if temporary buffering is used to achieve alignment; even if the entire
/// supplied buffer is hopelessly unaligned: the supplied data will be written
/// out some way or another during this call. This means there is no
/// requirement to care about flushing the temporary this->buffer after this
/// call is made. Note that the temporary this->buffer has no reason to be
/// touched by anything other than this function stack.
///
/// !!! NOTE !!!
/// There is a requirement to truncate the file after this call is made before
/// closing the file. If a crash occurs after a write() which was padded out
/// to the block alignment: the file size will reflect the padding when it is
/// opened at next startup; RocksDB will not detect its terminator character
/// sequence and consider this file corrupt.
/// !!!
///
/// - any offset
/// - any data
/// - any size
ircd::const_buffer
ircd::db::database::env::writable_file_direct::write(const const_buffer &buf_)
{
	const_buffer buf
	{
		aligned(logical_offset) && aligned(data(buf_))?
			write_aligned(buf_):
		!aligned(logical_offset)?
			write_unaligned_off(buf_):
			buf_
	};

	assert(aligned(logical_offset) || empty(buf));

	// buf can be empty here if it was entirely dealt with by the above
	// branches and there's nothing else to do here.
	if(empty(buf))
		return buf;

	// Branch on whether the buffer's address is aligned. If so, considering
	// the logical_offset is aligned here we are then finished.
	if(aligned(data(buf)))
		return write_aligned(buf);

	return write_unaligned_buf(buf);
}

/// * aligned offset
/// * unaligned data
/// - any size
ircd::const_buffer
ircd::db::database::env::writable_file_direct::write_unaligned_buf(const const_buffer &buf)
{
	assert(aligned(logical_offset));
	assert(!aligned(data(buf)));
	assert(!aligned(buf));

	// Window on the data between the given buffer's pointer and the next
	// alignment boundary.
	const const_buffer under_buf
	{
		buf, std::min(remain(uintptr_t(data(buf))), size(buf))
	};

	// Window on the data from the alignment boundary to the end of the
	// given buffer.
	const const_buffer remaining_buf
	{
		buf + size(under_buf)
	};

	assert(size(under_buf) <= size(buf));
	assert(size(under_buf) + size(remaining_buf) == size(buf));
	assert(data(buf) + size(under_buf) == data(remaining_buf));
	assert(aligned(data(remaining_buf)) || empty(remaining_buf));

	mutable_buffer dst(this->buffer);
	consume(dst, copy(dst, under_buf));
	consume(dst, copy(dst, remaining_buf));
	consume(dst, zero(dst));
	assert(empty(dst));

	// Flush the temporary buffer.
	_write__aligned(this->buffer, logical_offset);
	logical_offset += size(under_buf);
	return remaining_buf;
}

/// * unaligned offset
/// - any data
/// - any size
ircd::const_buffer
ircd::db::database::env::writable_file_direct::write_unaligned_off(const const_buffer &buf)
{
	assert(!aligned(logical_offset));

	// Window on the amount of buf we can take to fill up remaining space in
	// the temporary this->buffer
	const const_buffer src
	{
		buf, std::min(size(buf), buffer_remain())
	};

	// Window on the remaining space in the temporary this->buffer.
	const mutable_buffer dst
	{
		this->buffer + buffer_consumed()
	};

	// Window on the remaining space in dst after src is copied to dst, if any.
	const mutable_buffer pad
	{
		dst + size(src)
	};

	assert(size(dst) - size(pad) == size(src));
	assert(size(src) + size(pad) == buffer_remain());
	assert(size(src) + size(pad) + buffer_consumed() == alignment);
	assert(size(src) + buffer_consumed() != alignment || empty(pad));

	copy(dst, src);
	zero(pad);

	// Backtrack the logical_offset to the aligned offset where this->buffer's
	// data starts.
	const auto aligned_offset
	{
		align(logical_offset)
	};

	// Write the whole temporary this->buffer at the aligned offset.
	_write__aligned(this->buffer, aligned_offset);
	logical_offset += size(src);
	assert(aligned(logical_offset) || size(buf) < alignment);
	return const_buffer
	{
		buf + size(src)
	};
}

/// * aligned offset
/// * aligned data
/// - any size
ircd::const_buffer
ircd::db::database::env::writable_file_direct::write_aligned(const const_buffer &buf)
{
	assert(aligned(data(buf)));
	assert(aligned(logical_offset));

	// This portion at the end of buf did not fill out to the alignment.
	const const_buffer overflow
	{
		_write_aligned(buf, logical_offset)
	};

	// The aligned portion was written so the offset is incremented here.
	logical_offset += size(buf) - size(overflow);

	assert(aligned(logical_offset));
	assert(size(overflow) < alignment);
	assert(aligned(data(overflow)) || empty(overflow));
	assert(align(size(buf)) + size(overflow) == size(buf));
	assert(blocks(size(buf)) * alignment + size(overflow) == size(buf));

	if(!empty(overflow))
	{
		mutable_buffer dst(this->buffer);
		consume(dst, copy(dst, overflow));
		consume(dst, zero(dst));
		assert(empty(dst));

		_write__aligned(this->buffer, logical_offset);
		logical_offset += size(overflow);
		assert(!aligned(logical_offset));
	}

	return {};
}

/// * aligned data
/// * aligned offset
/// - any size
ircd::const_buffer
ircd::db::database::env::writable_file_direct::_write_aligned(const const_buffer &buf,
                                                              const uint64_t &offset)
{
	assert(aligned(data(buf)));
	assert(aligned(offset));

	// This portion will be written
	const const_buffer aligned_buf
	{
		buf, blocks(size(buf)) * alignment
	};

	// This trailing portion will be returned to caller
	const const_buffer ret
	{
		buf + size(aligned_buf), size(buf) - size(aligned_buf)
	};

	assert(!empty(aligned_buf) || size(buf) < alignment);
	assert(size(aligned_buf) + size(ret) == size(buf));
	assert(size(ret) < alignment);
	if(empty(aligned_buf))
	{
		assert(size(ret) == size(buf));
		return ret;
	}

	_write__aligned(aligned_buf, offset);
	return ret;
}

/// * aligned offset
/// * aligned data
/// * aligned size
ircd::const_buffer
ircd::db::database::env::writable_file_direct::_write__aligned(const const_buffer &buf,
                                                               const uint64_t &offset)
{
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' DIRECT fd:%d write:%p%s bytes:%zu%s offset:%zu%s (logical:%zu)",
			d.name,
			name,
			int(fd),
			data(buf),
			aligned(data(buf))? "" : "#AC",
			size(buf),
			aligned(size(buf))? "" : "#AC",
			offset,
			aligned(offset)? "" : "#AC",
			logical_offset
		};

	assert(aligned(buf));
	assert(aligned(offset));

	fs::write_opts wopts;
	wopts.priority = ionice;
	wopts.nodelay = nodelay;
	wopts.offset = offset;
	wopts.interruptible = false;
	fs::write(fd, buf, wopts);
	return {};
}

size_t
ircd::db::database::env::writable_file_direct::buffer_remain()
const
{
	return size(buffer) - buffer_consumed();
}

size_t
ircd::db::database::env::writable_file_direct::buffer_consumed()
const
{
	return likely(alignment != 0)?
		logical_offset % size(buffer):
		0UL;
}

size_t
ircd::db::database::env::writable_file_direct::blocks(const size_t &value)
const
{
	return likely(alignment != 0)?
		value / alignment:
		0UL;
}

size_t
ircd::db::database::env::writable_file_direct::remain(const size_t &value)
const
{
	return likely(alignment != 0)?
		alignment - (value - align(value)):
		0UL;
}

size_t
ircd::db::database::env::writable_file_direct::align(const size_t &value)
const
{
	return likely(alignment != 0)?
		value - (value % alignment):
		value;
}

bool
ircd::db::database::env::writable_file_direct::aligned(const const_buffer &buf)
const
{
	return buffer::aligned(buf, alignment);
}

bool
ircd::db::database::env::writable_file_direct::aligned(const void *const &value)
const
{
	return aligned(size_t(value));
}

bool
ircd::db::database::env::writable_file_direct::aligned(const size_t &value)
const
{
	return (alignment == 0) || (value % alignment == 0UL);
}

//
// sequential_file
//

decltype(ircd::db::database::env::sequential_file::default_opts)
ircd::db::database::env::sequential_file::default_opts
{
	.mode = std::ios_base::in,
	.sequential = true,
};

ircd::db::database::env::sequential_file::sequential_file(database *const &d,
                                                          const std::string &path,
                                                          const EnvOptions &env_opts)
try
:d
{
	*d
}
,name
{
	fs::filename(_namebuf, path)
}
,opts{[&env_opts]
{
	fs::fd::opts ret{default_opts};
	ret.direct = env_opts.use_direct_reads;
	return ret;
}()}
,fd
{
	path, this->opts
}
,_buffer_align
{
	opts.direct?
		fs::block_size(fd):
		1
}
,ionice
{
	ctx::ionice(ctx::cur())
}
,aio
{
	// When this flag is false then AIO operations are never used for this
	// file; if true, AIO may be used if available and/or other conditions.
	// Currently the /proc filesystem doesn't like AIO.
	!startswith(path, "/proc/")
}
{
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] opened seqfile:%p fd:%d bs:%zu '%s'",
			d->name,
			this,
			int(fd),
			_buffer_align,
			path
		};
}
catch(const std::system_error &e)
{
	// Set the level to downplay some errors which the user shouldn't
	// be alerted to with a log message under normal operations.
	const log::level level
	{
		is(e.code(), std::errc::no_such_file_or_directory)?
			log::level::DERROR:
			log::level::ERROR
	};

	log::logf
	{
		log, level, "[%s] opening seqfile:%p `%s' (%d) :%s",
		d->name,
		this,
		path,
		e.code().value(),
		e.what()
	};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "[%s] opening seqfile:%p `%s' :%s",
		d->name,
		this,
		path,
		e.what()
	};
}

ircd::db::database::env::sequential_file::~sequential_file()
noexcept
{
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' close fd:%d",
			d.name,
			name,
			int(fd)
		};
}

rocksdb::Status
ircd::db::database::env::sequential_file::Read(size_t length,
                                               Slice *const result,
                                               char *const scratch)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::unique_lock lock
	{
		mutex, std::try_to_lock
	};

	// RocksDB sez that this call requires "External synchronization" i.e the
	// caller, not this class is responsible for exclusion. We assert anyway.
	if(unlikely(!bool(lock)))
		ircd::terminate
		{
			"[%s]'%s' Unexpected concurrent access to seqfile:%p",
			d.name,
			name,
			this
		};

	assert(result);
	assert(scratch);
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' read:%p offset:%zu length:%zu scratch:%p",
			d.name,
			name,
			result,
			offset,
			length,
			scratch
		};

	fs::read_opts opts;
	opts.offset = offset;
	opts.priority = ionice;
	opts.aio = this->aio;
	opts.all = true;
	const mutable_buffer buf
	{
		scratch, length
	};

	const const_buffer read
	{
		fs::read(fd, buf, opts)
	};

	*result = slice(read);
	this->offset += size(read);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' read:%p offset:%zu length:%zu scratch:%p :%s",
		d.name,
		name,
		result,
		offset,
		length,
		scratch,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' read:%p offset:%zu length:%zu scratch:%p :%s",
		d.name,
		name,
		result,
		offset,
		length,
		scratch,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::sequential_file::PositionedRead(uint64_t offset,
                                                         size_t length,
                                                         Slice *const result,
                                                         char *const scratch)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::unique_lock lock
	{
		mutex, std::try_to_lock
	};

	if(unlikely(!bool(lock)))
		ircd::terminate
		{
			"[%s] Unexpected concurrent access to seqfile %p",
			d.name,
			this
		};

	assert(result);
	assert(scratch);
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' offset:%zu positioned read:%p offset:%zu length:%zu scratch:%p",
			d.name,
			name,
			this->offset,
			result,
			offset,
			length,
			scratch
		};

	fs::read_opts opts;
	opts.offset = offset;
	opts.priority = ionice;
	opts.aio = this->aio;
	opts.all = false;
	const mutable_buffer buf
	{
		scratch, length
	};

	const const_buffer read
	{
		fs::read(fd, buf, opts)
	};

	*result = slice(read);
	this->offset = std::max(this->offset, off_t(offset + size(read)));
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' positioned read:%p offset:%zu length:%zu scratch:%p :%s",
		d.name,
		name,
		result,
		offset,
		length,
		scratch,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' positioned read:%p offset:%zu length:%zu scratch:%p :%s",
		d.name,
		name,
		result,
		offset,
		length,
		scratch,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::sequential_file::Skip(uint64_t size)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;
	const std::unique_lock lock
	{
		mutex, std::try_to_lock
	};

	// RocksDB sez that this call requires "External synchronization" i.e the
	// caller, not this class is responsible for exclusion. We assert anyway.
	if(unlikely(!bool(lock)))
		ircd::terminate
		{
			"[%s] Unexpected concurrent access to seqfile %p",
			d.name,
			this
		};

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			"[%s]'%s' offset:zu skip:%zu",
			d.name,
			name,
			offset,
			size
		};

	offset += size;
	return Status::OK();
}
catch(const panic &e)
{
	log::critical
	{
		log, "[%s]'%s' :%s",
		d.name,
		name,
		e.what(),
	};

	return Status::Busy();
}

rocksdb::Status
ircd::db::database::env::sequential_file::InvalidateCache(size_t offset,
                                                          size_t length)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			"[%s]'%s' invalidate cache offset:%zu length:%zu",
			d.name,
			name,
			offset,
			length
		};

	if(opts.direct)
		return Status::OK();

	fs::evict(fd, length, offset);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		"[%s]'%s' invalidate cache offset:%zu length:%zu :%s",
		d.name,
		name,
		offset,
		length,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		"[%s]'%s' invalidate cache offset:%zu length:%zu :%s",
		d.name,
		name,
		offset,
		length,
		e.what()
	};

	return error_to_status{e};
}

bool
ircd::db::database::env::sequential_file::use_direct_io()
const noexcept
{
	return opts.direct;
}

size_t
ircd::db::database::env::sequential_file::GetRequiredBufferAlignment()
const noexcept
{
	const auto &ret
	{
		_buffer_align
	};

	return ret;
}

//
// random_access_file
//

decltype(ircd::db::database::env::random_access_file::default_opts)
ircd::db::database::env::random_access_file::default_opts
{
	.mode = std::ios_base::in,
	.random = true,
};

decltype(ircd::db::database::env::random_access_file::read_count)
ircd::db::database::env::random_access_file::read_count
{
	{ "name", "ircd.db.read.count" },
};

decltype(ircd::db::database::env::random_access_file::read_bytes)
ircd::db::database::env::random_access_file::read_bytes
{
	{ "name", "ircd.db.read.bytes" },
};

decltype(ircd::db::database::env::random_access_file::read_dedup_count)
ircd::db::database::env::random_access_file::read_dedup_count
{
	{ "name", "ircd.db.read.dedup.count" },
};

decltype(ircd::db::database::env::random_access_file::read_dedup_bytes)
ircd::db::database::env::random_access_file::read_dedup_bytes
{
	{ "name", "ircd.db.read.dedup.bytes" },
};

decltype(ircd::db::database::env::random_access_file::read_multi_count)
ircd::db::database::env::random_access_file::read_multi_count
{
	{ "name", "ircd.db.read.multi.count" },
};

decltype(ircd::db::database::env::random_access_file::read_multi_bytes)
ircd::db::database::env::random_access_file::read_multi_bytes
{
	{ "name", "ircd.db.read.multi.bytes" },
};

ircd::db::database::env::random_access_file::random_access_file(database *const &d,
                                                                const std::string &path,
                                                                const EnvOptions &env_opts)
try
:d
{
	*d
}
,name
{
	fs::filename(_namebuf, path)
}
,opts{[&env_opts]
{
	fs::fd::opts ret{default_opts};
	ret.direct = env_opts.use_direct_reads;
	return ret;
}()}
,fd
{
	path, this->opts
}
,_buffer_align
{
	opts.direct?
		fs::block_size(fd):
		1
}
,ionice
{
	ctx::ionice(ctx::cur())
}
,aio
{
	// When this flag is false then AIO operations are never used for this
	// file; if true, AIO may be used if available and/or other conditions.
	// Currently the /proc filesystem doesn't like AIO.
	!startswith(name, "/proc/")
}
{
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] opened rfile:%p fd:%d bs:%zu `%s'",
			d->name,
			this,
			int(fd),
			_buffer_align,
			path,
		};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "[%s] opening rfile:%p `%s' :%s",
		d->name,
		this,
		path,
		e.what()
	};
}

ircd::db::database::env::random_access_file::~random_access_file()
noexcept
{
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d close",
			d.name,
			name,
			int(fd)
		};
}

rocksdb::Status
ircd::db::database::env::random_access_file::Prefetch(uint64_t offset,
                                                      size_t length)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' prefetch offset:%zu length:%zu",
			d.name,
			name,
			offset,
			length
		};

	// Note RocksDB does not call our prefetch() when using direct IO.
	assert(!this->opts.direct);

	fs::prefetch(fd, length, offset);
	return Status::OK();
}
catch(const std::system_error &e)
{
	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' prefetch offset:%zu length:%zu :%s",
		d.name,
		name,
		offset,
		length,
		e.what()
	};

	return error_to_status{e};
}

#if defined(IRCD_DB_HAS_ENV_MULTIREAD) && !defined(IRCD_DB_HAS_MULTIREAD_FIX)
#warning "RocksDB MultiRead is buggy in this version. Please upgrade to 6.12.6+"
#endif

#if defined(IRCD_DB_HAS_ENV_MULTIREAD)
rocksdb::Status
ircd::db::database::env::random_access_file::MultiRead(rocksdb::ReadRequest *const req,
                                                       size_t num)
noexcept try
{
	assert(req);
	const ctx::uninterruptible::nothrow ui;

	fs::read_op op[num];
	mutable_buffer buf[num];
	fs::read_opts opts[num];
	for(size_t i(0); i < num; ++i)
	{
		opts[i].offset = req[i].offset;
		opts[i].priority = ionice;
		opts[i].aio = this->aio;
		opts[i].all = false;
		buf[i] =
		{
			req[i].scratch, req[i].len
		};

		op[i].fd = std::addressof(this->fd);
		op[i].opts = opts + i;
		op[i].bufs =
		{
			buf + i, 1
		};

		if constexpr(RB_DEBUG_DB_ENV)
			log::debug
			{
				log, "[%s]'%s' multiread:%zu:%zu offset:%zu length:%zu scratch:%p",
				d.name,
				name,
				i,
				num,
				req[i].offset,
				req[i].len,
				req[i].scratch,
			};

		assert(!this->opts.direct || buffer::aligned(buf[i], _buffer_align));
	}

	const auto bytes
	{
		fs::read({op, num})
	};

	for(size_t i(0); i < num; ++i) try
	{
		if(op[i].eptr)
			std::rethrow_exception(op[i].eptr);

		assert(op[i].ret <= size(buf[i]));
		const const_buffer read
		{
			buf[i], op[i].ret
		};

		req[i].status = Status::OK();
		req[i].result = slice(read);
		assert(req[i].result.size() == req[i].len);

		read_bytes += size(read);
		read_count += 1;
	}
	catch(const std::exception &e)
	{
		log::error
		{
			log, "[%s]'%s' multiread:%zu:%zu offset:%zu length:%zu :%s",
			d.name,
			name,
			i,
			num,
			req[i].offset,
			req[i].len,
			e.what(),
		};

		req[i].status = error_to_status{e};
	}

	read_multi_bytes += bytes;
	read_multi_count += 1;
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' multiread:%p num:%zu :%s",
		d.name,
		name,
		req,
		num,
		e.what(),
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' multiread:%p num:%zu :%s",
		d.name,
		name,
		req,
		num,
		e.what(),
	};

	return error_to_status{e};
}
#else
#warning "RocksDB MultiRead is not supported for this build."
#endif IRCD_DB_HAS_ENV_MULTIREAD

rocksdb::Status
ircd::db::database::env::random_access_file::Read(uint64_t offset,
                                                  size_t length,
                                                  Slice *const result,
                                                  char *const scratch)
const noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	assert(result);
	assert(scratch);
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' read:%p offset:%zu length:%zu scratch:%p",
			d.name,
			name,
			result,
			offset,
			length,
			scratch
		};

	fs::read_opts opts;
	opts.offset = offset;
	opts.priority = ionice;
	opts.aio = this->aio;
	opts.all = !this->opts.direct;
	const mutable_buffer buf
	{
		scratch, length
	};

	bool is_pending {false};
	for(const auto &p : pending)
	{
		assert(!p.buf || p.opts);
		if(!p.buf || buffer::size(*p.buf) != buffer::size(buf))
			continue;

		if(p.opts->offset != opts.offset)
			continue;

		is_pending = true;
		break;
	}

	struct waiting *waiter {nullptr};
	struct pending *pender {nullptr};
	const unwind uw{[&]
	{
		if(waiter)
			*waiter = {};

		if(pender)
			*pender = {};
	}};

	ctx::latch latch {1};
	if(is_pending)
		for(auto &w : waiting)
			if(!w.buf)
			{
				w.buf = &buf;
				w.opts = &opts;
				w.latch = &latch;
				waiter = &w;
				break;
			}

	if(!is_pending && !waiter)
		for(auto &p : pending)
			if(!p.buf)
			{
				p.buf = &buf;
				p.opts = &opts;
				pender = &p;
				break;
			}

	if(waiter)
	{
		latch.wait();
		if(waiter->read)
		{
			assert(!opts.all || waiter->read == length);
			*result = slice(mutable_buffer(buf, waiter->read));
			return Status::OK();
		}
	}

	assert(!this->opts.direct || buffer::aligned(buf, _buffer_align));
	const auto read
	{
		fs::read(fd, buf, opts)
	};

	if(pender)
		for(auto &w : waiting)
		{
			assert(w.buf || (!w.opts && !w.latch));
			if(!w.buf || buffer::size(*w.buf) != buffer::size(buf))
				continue;

			if(w.opts->offset != opts.offset)
				continue;

			w.read = copy(*w.buf, read);
			read_dedup_bytes += w.read;
			read_dedup_count += 1;
			w.latch->count_down();
		}

	assert(!opts.all || size(read) == length);
	*result = slice(read);
	read_bytes += size(read);
	read_count += 1;
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' read:%p offset:%zu length:%zu scratch:%p :%s",
		d.name,
		name,
		result,
		offset,
		length,
		scratch,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' read:%p offset:%zu length:%zu scratch:%p :%s",
		d.name,
		name,
		result,
		offset,
		length,
		scratch,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::random_access_file::InvalidateCache(size_t offset,
                                                             size_t length)
noexcept
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' invalidate cache offset:%zu length:%zu",
			d.name,
			name,
			offset,
			length
		};

	if(opts.direct)
		return Status::OK();

	fs::evict(fd, length, offset);
	return Status::OK();
}

size_t
ircd::db::database::env::random_access_file::GetUniqueId(char *const id,
                                                         size_t max_size)
const noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' get unique id:%p max_size:%zu",
			d.name,
			name,
			id,
			max_size
		};

	const mutable_buffer buf
	{
		id, max_size
	};

	//return size(fs::uuid(fd, buf));
	return 0;
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' GetUniqueId id:%p max_size:%zu :%s",
		d.name,
		name,
		id,
		max_size,
		e.what()
	};

	return 0;
}

void
ircd::db::database::env::random_access_file::Hint(AccessPattern pattern)
noexcept
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' hint %s",
			d.name,
			name,
			reflect(pattern)
		};
}

bool
ircd::db::database::env::random_access_file::use_direct_io()
const noexcept
{
	return opts.direct;
}

size_t
ircd::db::database::env::random_access_file::GetRequiredBufferAlignment()
const noexcept
{
	const auto &ret
	{
		_buffer_align
	};

	return ret;
}

//
// random_rw_file
//

decltype(ircd::db::database::env::random_rw_file::default_opts)
ircd::db::database::env::random_rw_file::default_opts
{
	.mode = std::ios_base::in | std::ios_base::out,
	.random = true,
};

ircd::db::database::env::random_rw_file::random_rw_file(database *const &d,
                                                        const std::string &path,
                                                        const EnvOptions &env_opts)
try
:d
{
	*d
}
,name
{
	fs::filename(_namebuf, path)
}
,opts{[&env_opts]
{
	fs::fd::opts ret{default_opts};
	ret.direct = env_opts.use_direct_reads && env_opts.use_direct_writes;
	return ret;
}()}
,fd
{
	path, this->opts
}
,_buffer_align
{
	opts.direct?
		fs::block_size(fd):
		1
}
,ionice
{
	ctx::ionice(ctx::cur())
}
,aio
{
	true
}
{
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] opened rwfile:%p fd:%d bs:%zu `%s'",
			d->name,
			this,
			int(fd),
			_buffer_align,
			path
		};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "[%s] opening rwfile:%p `%s' :%s",
		d->name,
		this,
		path,
		e.what()
	};
}

ircd::db::database::env::random_rw_file::~random_rw_file()
noexcept
{
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d closed '%s'",
			d.name,
			name,
			int(fd)
		};
}

rocksdb::Status
ircd::db::database::env::random_rw_file::Close()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d close",
			d.name,
			name,
			int(fd)
		};

	this->fd = fs::fd{};
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		"[%s]'%s' close :%s",
		d.name,
		name,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		"[%s]'%s' close :%s",
		d.name,
		name,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::random_rw_file::Fsync()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d fsync",
			d.name,
			int(fd),
		};

	fs::sync_opts opts;
	opts.metadata = bool(paranoid_sync);
	opts.priority = ionice;
	opts.nodelay = nodelay;
	fs::sync(fd, opts);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		"[%s]'%s' fd:%d fsync :%s",
		d.name,
		name,
		int(fd),
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		"[%s]'%s' fd:%d fsync :%s",
		d.name,
		name,
		int(fd),
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::random_rw_file::Sync()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d sync",
			d.name,
			int(fd),
			this
		};

	fs::sync_opts opts;
	opts.metadata = true;
	opts.priority = ionice;
	opts.nodelay = nodelay;
	fs::sync(fd, opts);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		"[%s]'%s' fd:%d sync :%s",
		d.name,
		name,
		int(fd),
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		"[%s]'%s' fd:%d sync :%s",
		d.name,
		name,
		int(fd),
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::random_rw_file::Flush()
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d flush%s",
			d.name,
			int(fd),
			!db::paranoid_sync?
				" (noop)"_sv:
				string_view{},
		};

	if(db::paranoid_sync)
	{
		fs::sync_opts opts;
		opts.metadata = false;
		opts.priority = ionice;
		opts.nodelay = nodelay;
		fs::sync(fd, opts);
	}

	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		"[%s]'%s' fd:%d flush :%s",
		d.name,
		name,
		int(fd),
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		"[%s]'%s' fd:%d flush :%s",
		d.name,
		name,
		int(fd),
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::random_rw_file::Read(uint64_t offset,
                                              size_t length,
                                              Slice *const result,
                                              char *const scratch)
const noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	assert(result);
	assert(scratch);
	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' read:%p offset:%zu length:%zu scratch:%p",
			d.name,
			name,
			result,
			offset,
			length,
			scratch
		};

	fs::read_opts opts;
	opts.offset = offset;
	opts.priority = ionice;
	opts.aio = this->aio;
	opts.all = !this->opts.direct;
	const mutable_buffer buf
	{
		scratch, length
	};

	const auto read
	{
		fs::read(fd, buf, opts)
	};

	assert(!opts.all || size(read) == length);
	*result = slice(read);
	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' read:%p offset:%zu length:%zu scratch:%p :%s",
		d.name,
		name,
		result,
		offset,
		length,
		scratch,
		e.what()
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' read:%p offset:%zu length:%zu scratch:%p :%s",
		d.name,
		name,
		result,
		offset,
		length,
		scratch,
		e.what()
	};

	return error_to_status{e};
}

rocksdb::Status
ircd::db::database::env::random_rw_file::Write(uint64_t offset,
                                               const Slice &slice)
noexcept try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s]'%s' fd:%d write:%p length:%zu offset:%zu",
			d.name,
			name,
			int(fd),
			data(slice),
			size(slice),
			offset
		};

	const const_buffer buf
	{
		data(slice), size(slice)
	};

	const auto read
	{
		fs::write(fd, buf, offset)
	};

	return Status::OK();
}
catch(const std::system_error &e)
{
	log::error
	{
		log, "[%s]'%s' fd:%d write:%p length:%zu offset:%zu",
		d.name,
		name,
		int(fd),
		data(slice),
		size(slice),
		offset
	};

	return error_to_status{e};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s]'%s' fd:%d write:%p length:%zu offset:%zu",
		d.name,
		name,
		int(fd),
		data(slice),
		size(slice),
		offset
	};

	return error_to_status{e};
}

bool
ircd::db::database::env::random_rw_file::use_direct_io()
const noexcept
{
	return opts.direct;
}

size_t
ircd::db::database::env::random_rw_file::GetRequiredBufferAlignment()
const noexcept
{
	const auto &ret
	{
		_buffer_align
	};

	return ret;
}

//
// directory
//

ircd::db::database::env::directory::directory(database *const &d,
                                              const std::string &name,
                                              std::unique_ptr<Directory> defaults)
:d{*d}
,defaults{std::move(defaults)}
{
}

ircd::db::database::env::directory::~directory()
noexcept
{
}

rocksdb::Status
ircd::db::database::env::directory::Fsync()
noexcept
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(RB_DEBUG_DB_ENV)
		log::debug
		{
			log, "[%s] directory:%p fsync",
			d.name,
			this
		};

	return defaults->Fsync();
}

//
// file_lock
//

ircd::db::database::env::file_lock::file_lock(database *const &d)
:d{*d}
{
}

ircd::db::database::env::file_lock::~file_lock()
noexcept
{
}

///////////////////////////////////////////////////////////////////////////////
//
// db/database/env/state.h
//

//
// env::state::state
//

ircd::db::database::env::state::state(database *const &d)
:d{*d}
{
	for(size_t i(0); i < pool.size(); ++i)
		pool.at(i) = std::make_unique<struct pool>(this->d, Priority(i));
}

ircd::db::database::env::state::~state()
noexcept
{
	log::debug
	{
		log, "[%s] Shutting down environment...",
		d.name
	};
}

//
// state::pool
//

decltype(ircd::db::database::env::state::pool::stack_size)
ircd::db::database::env::state::pool::stack_size
{
	{ "name",     "ircd.db.env.pool.stack_size" },
	{ "default",  long(128_KiB)                 },
};

decltype(ircd::db::database::env::state::pool::hysteresis_high)
ircd::db::database::env::state::pool::hysteresis_high
{
	{ "name",     "ircd.db.env.pool.hyst.high" },
	{ "default",  -1L                          },
};

decltype(ircd::db::database::env::state::pool::hysteresis_low)
ircd::db::database::env::state::pool::hysteresis_low
{
	{ "name",     "ircd.db.env.pool.hyst.low" },
	{ "default",  -1L                         },
};

//
// state::pool::pool
//

ircd::db::database::env::state::pool::pool(database &d,
                                           const Priority &pri)
:d{d}
,pri{pri}
,iopri
{
	make_ioprio(this->pri)
}
,name
{
	fmt::sprintf
	{
		namebuf, "db.%s", reflect(this->pri)
	}
}
,popts
{
	.stack_size = size_t(stack_size),
	.limit = 1, // usually raised later by rocksdb callback
	.hysteresis = this->pri >= Priority::HIGH?
		size_t(hysteresis_high):
		size_t(hysteresis_low),
	.queue_max_soft = -1UL,
	.queue_max_blocking = false, // never stalls rocksdb
	.dynamic = true,
	.nice = make_nice(this->pri),
	.ionice = make_nice(iopri),
}
,p
{
	this->name, this->popts
}
{
}

ircd::db::database::env::state::pool::~pool()
noexcept
{
	join();
}

void
ircd::db::database::env::state::pool::join()
try
{
	if(!tasks.empty() || p.pending())
		log::warning
		{
			log, "[%s] Waiting for tasks:%zu queued:%zu active:%zu in pool '%s'",
			d.name,
			tasks.size(),
			p.queued(),
			p.active(),
			ctx::name(p)
		};

	this->wait();
	assert(!p.pending());
	assert(tasks.empty());
	p.join();

	log::debug
	{
		log, "[%s] Terminated pool '%s'.",
		d.name,
		ctx::name(p)
	};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "[%s] Environment pool '%s' join :%s",
		d.name,
		ctx::name(p),
		e.what()
	};

	throw;
}

void
ircd::db::database::env::state::pool::wait()
{
	dock.wait([this]
	{
		return tasks.empty() && !p.pending();
	});
}

size_t
ircd::db::database::env::state::pool::cancel(void *const &tag)
{
	size_t i(0);
	auto it(begin(tasks));
	while(it != end(tasks))
	{
		auto &task(*it);
		log::debug
		{
			log, "[%s] pool:%s tasks:%zu cancel#%zu task:%lu func:%p cancel:%p arg:%p tag:%p",
			d.name,
			ctx::name(p),
			tasks.size(),
			i,
			task._id,
			task.func,
			task.cancel,
			task.arg,
			tag
		};

		task.cancel(task.arg);
		it = tasks.erase(it);
		++i;
	}

	dock.notify_all();
	return i;
}

void
ircd::db::database::env::state::pool::operator()(task &&task)
{
	assert(task._id == 0);
	task._id = ++taskctr;
	tasks.emplace_back(std::move(task));

	log::debug
	{
		log, "[%s] pool:%s queue:%zu QUEUE task:%lu func:%p arg:%p",
		this->d.name,
		ctx::name(p),
		tasks.size(),
		tasks.back()._id,
		tasks.back().func,
		tasks.back().arg,
	};

	auto handle
	{
		std::bind(&pool::worker, this)
	};

	p(std::move(handle));
}

void
ircd::db::database::env::state::pool::worker()
{
	if(tasks.empty())
		return;

	const ctx::uninterruptible::nothrow ui;
	const auto task{std::move(tasks.front())};
	tasks.pop_front();

	log::debug
	{
		log, "[%s] pool:%s queue:%zu ENTER task:%lu func:%p arg:%p",
		this->d.name,
		ctx::name(p),
		tasks.size(),
		task._id,
		task.func,
		task.arg,
	};

	const ctx::slice_usage_warning message
	{
		"[%s] pool:%s task:%p",
		this->d.name,
		ctx::name(p),
		task.func
	};

	// Execute the task
	task.func(task.arg);

	log::debug
	{
		log, "[%s] pool:%s queue:%zu LEAVE task:%zu func:%p arg:%p",
		this->d.name,
		ctx::name(p),
		tasks.size(),
		task._id,
		task.func,
		task.arg,
	};

	dock.notify_all();
}
