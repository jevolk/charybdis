// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2019 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#pragma once
#define HAVE_IRCD_DB_PORT_H

// !!! EXPERIMENTAL !!!
//
// This file is special; even within the context of embedding RocksDB through
// its env interface. The functionality provided here is NOT done via
// overriding virtual interfaces called by RocksDB like with the rest of env.
// This functionality is deemed too critical for runtime virtual interfaces.
//
// Instead, the definitions we provide override those that RocksDB uses at
// link-time during the compilation of libircd. Interface declarations are not
// provided by RocksDB in its include path either, thus our interface here must
// match the rocksdb::port interface.
//
// Unfortunately if the rocksdb::port interface partially changes and we leave
// unresolved symbols at link time that may be bad, and go silently unnoticed.
//
// !!! EXPERIMENTAL !!!

namespace rocksdb::port
{
	using namespace ircd;

	struct Mutex;
	struct CondVar;
	struct RWMutex;
}

class rocksdb::port::Mutex
{
	friend class CondVar;

	union
	{
		ctx::mutex mu;
		pthread_mutex_t mu_;
	};

  public:
	void Lock() noexcept;
	void Unlock() noexcept;
	void AssertHeld() const noexcept;

	Mutex() noexcept;
	Mutex(bool adaptive) noexcept;
	Mutex(const Mutex &) = delete;
	Mutex &operator=(const Mutex &) = delete;
	~Mutex() noexcept;
};

class rocksdb::port::CondVar
{
	union
	{
		ctx::condition_variable cv;
		pthread_cond_t cv_;
	};

	Mutex *mu;

  public:
	void Wait() noexcept;
	bool TimedWait(uint64_t abs_time_us) noexcept; // Returns true if timeout occurred
	void Signal() noexcept;
	void SignalAll() noexcept;

	CondVar(Mutex *mu) noexcept;
	~CondVar() noexcept;
};

class rocksdb::port::RWMutex
{
	union
	{
		ctx::shared_mutex mu;
		pthread_rwlock_t mu_;
	};

  public:
	void ReadLock() noexcept;
	void WriteLock() noexcept;
	void ReadUnlock() noexcept;
	void WriteUnlock() noexcept;

	RWMutex() noexcept;
	RWMutex(const RWMutex &) = delete;
	RWMutex &operator=(const RWMutex &) = delete;
	~RWMutex() noexcept;
};
