// The Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2021 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#include <dlfcn.h>
#include <CL/cl.h>
#include <CL/cl_ext.h>

// Util
namespace ircd::cl
{
	static bool is_error(const int &code) noexcept;
	static int throw_on_error(const int &code);
	template<int maybe = CL_SUCCESS, class func, class... args> static int call(func&&, args&&...);
	template<class T = string_view, int maybe = CL_SUCCESS, class F, class id, class param> static T info(F&&, const id &, const param &, const mutable_buffer &, T default_ = {});
	template<class T = string_view, int maybe = CL_SUCCESS, class F, class id0, class id1, class param> static T info(F&&, const id0 &, const id1 &, const param &, const mutable_buffer &, T default_ = {});

	static uint query_warp_size(cl_context, cl_device_id);
}

// Runtime state
namespace ircd::cl
{
	static const size_t
	OPTION_MAX {8},
	PLATFORM_MAX {8},
	DEVICE_MAX {8};

	static uint
	options,
	platforms,
	devices[PLATFORM_MAX];

	static char
	option[OPTION_MAX][256];

	static void
	*linkage;

	static cl_platform_id
	platform[PLATFORM_MAX];

	static cl_device_id
	device[PLATFORM_MAX][DEVICE_MAX];

	static struct version
	{
		int major, minor;
	}
	api[PLATFORM_MAX][DEVICE_MAX];

	static cl_context
	primary;

	extern struct stats
	primary_stats;

	static cl_command_queue
	queue[PLATFORM_MAX][DEVICE_MAX];

	static void handle_notify(const char *, const void *, size_t, void *) noexcept;
}

struct ircd::cl::stats
{
	template<class T>
	using item = ircd::stats::item<T>;

	item<uint64_t>
	sync_count,
	flush_count,
	alloc_count,
	alloc_bytes,
	dealloc_count,
	dealloc_bytes,
	work_waits,
	work_waits_async,
	work_errors,
	work_completes,
	exec_tasks,
	exec_kern_tasks,
	exec_kern_threads,
	exec_kern_groups,
	exec_write_tasks,
	exec_write_bytes,
	exec_read_tasks,
	exec_read_bytes,
	exec_copy_tasks,
	exec_copy_bytes,
	exec_barrier_tasks;
};

decltype(ircd::cl::log)
ircd::cl::log
{
	"cl"
};

decltype(ircd::cl::version_api)
ircd::cl::version_api
{
	"OpenCL", info::versions::API, CL_TARGET_OPENCL_VERSION,
	{
		#if defined(CL_VERSION_MAJOR) && defined(CL_VERSION_MINOR) && defined(CL_VERSION_PATCH)
		CL_VERSION_MAJOR(CL_TARGET_OPENCL_VERSION),
		CL_VERSION_MINOR(CL_TARGET_OPENCL_VERSION),
		CL_VERSION_PATCH(CL_TARGET_OPENCL_VERSION),
		#endif
	}
};

decltype(ircd::cl::version_abi)
ircd::cl::version_abi
{
	"OpenCL", info::versions::ABI
};

decltype(ircd::cl::enable)
ircd::cl::enable
{
	{ "name",      "ircd.cl.enable"  },
	{ "default",   true              },
	{ "persist",   false             },
};

decltype(ircd::cl::profile_queue)
ircd::cl::profile_queue
{
	{ "name",      "ircd.cl.profile.queue"  },
	{ "default",   false                    },
	{ "persist",   false                    },
};

decltype(ircd::cl::nice_rate)
ircd::cl::nice_rate
{
	{ "name",      "ircd.cl.nice.rate"  },
	{ "default",   1L                   },
};

decltype(ircd::cl::watchdog_tsc)
ircd::cl::watchdog_tsc
{
	{ "name",      "ircd.cl.watchdog.tsc"  },
	{ "default",   268'435'456L            },
};

decltype(ircd::cl::path)
ircd::cl::path
{
	{ "name",      "ircd.cl.path"  },
	{ "default",   "libOpenCL.so"  },
	{ "persist",   false           },
};

decltype(ircd::cl::envs)
ircd::cl::envs
{
	{
		{ "name",      "LP_NUM_THREADS" },
		{ "default",   "0"              },
	},
	{
		{ "name",      "MESA_NO_MINMAX_CACHE" },
		{ "default",   "true"                 },
	},
	{
		{ "name",      "MESA_GLSL_CACHE_DISABLE" },
		{ "default",   "true"                    },
	},
	{
		{ "name",      "AMD_DEBUG"           },
		{ "default",   "nogfx,reserve_vmid"  },
	},
	{
		{ "name",      "R600_DEBUG"  },
		{ "default",   "forcedma"    },
	},
};

decltype(ircd::cl::primary_stats)
ircd::cl::primary_stats
{
	{ { "name", "ircd.cl.sync.count"          } },
	{ { "name", "ircd.cl.flush.count"         } },
	{ { "name", "ircd.cl.alloc.count"         } },
	{ { "name", "ircd.cl.alloc.bytes"         } },
	{ { "name", "ircd.cl.dealloc.count"       } },
	{ { "name", "ircd.cl.dealloc.bytes"       } },
	{ { "name", "ircd.cl.work.waits"          } },
	{ { "name", "ircd.cl.work.waits.async"    } },
	{ { "name", "ircd.cl.work.errors"         } },
	{ { "name", "ircd.cl.work.completes"      } },
	{ { "name", "ircd.cl.exec.tasks"          } },
	{ { "name", "ircd.cl.exec.kern.tasks"     } },
	{ { "name", "ircd.cl.exec.kern.threads"   } },
	{ { "name", "ircd.cl.exec.kern.groups"    } },
	{ { "name", "ircd.cl.exec.write.tasks"    } },
	{ { "name", "ircd.cl.exec.write.bytes"    } },
	{ { "name", "ircd.cl.exec.read.tasks"     } },
	{ { "name", "ircd.cl.exec.read.bytes"     } },
	{ { "name", "ircd.cl.exec.copy.tasks"     } },
	{ { "name", "ircd.cl.exec.copy.bytes"     } },
	{ { "name", "ircd.cl.exec.barrier.tasks"  } },
};

//
// init
//

ircd::cl::init::init()
{
	if(!enable)
	{
		log::dwarning
		{
			log, "OpenCL hardware acceleration is not available or enabled."
		};

		return;
	}

	const ctx::posix::enable_pthread enable_pthread;

	// Link the libraries.
	if(!init_libs())
		return;

	// Get the platforms.
	if(!init_platforms())
		return;

	// Report the platforms.
	log_platform_info();

	// Get the devices.
	if(!init_devices())
		return;

	// Report the devices.
	log_dev_info();

	// Various other inits.
	init_ctxs();
}

ircd::cl::init::~init()
noexcept
{
	if(!linkage)
		return;

	log::debug
	{
		log, "Shutting down OpenCL...",
	};

	const ctx::posix::enable_pthread enable_pthread;
	fini_ctxs();
	fini_libs();
}

bool
ircd::cl::init::init_libs()
{
	const std::string &path
	{
		cl::path
	};

	if(path.empty())
		return false;

	// Setup options
	for(const auto &item : envs)
	{
		assert(options < OPTION_MAX);
		fmt::sprintf
		{
			option[options], "%s=%s",
			item.name,
			string_view{item},
		};

		sys::call(putenv, option[options++]);
	}

	// Load the pipe.
	assert(!linkage);
	if(!(linkage = dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL)))
		return false;

	return true;
}

void
ircd::cl::init::fini_libs()
{
	if(likely(linkage))
		dlclose(linkage);
}

size_t
ircd::cl::init::init_platforms()
{
	// OpenCL sez platform=null is implementation defined.
	constexpr auto ignore(CL_INVALID_PLATFORM);
	info<string_view, ignore>(clGetPlatformInfo, nullptr, CL_PLATFORM_VERSION, version_abi.string);

	// Get the platforms.
	call(clGetPlatformIDs, PLATFORM_MAX, platform, &platforms);

	return platforms;
}

size_t
ircd::cl::init::init_devices()
{
	// Get the devices.
	size_t devices_total(0);
	for(size_t i(0); i < platforms; ++i)
	{
		static const auto type
		{
			CL_DEVICE_TYPE_GPU | CL_DEVICE_TYPE_ACCELERATOR
		};

		call(clGetDeviceIDs, platform[i], type, DEVICE_MAX, device[i], devices + i);
		devices_total += devices[i];
	}

	// Gather the API versions for the devices.
	for(size_t i(0); i < platforms; ++i)
		for(size_t j(0); j < devices[i]; ++j) try
		{
			// OpenCL sez:
			// OpenCL<space><major_version.minor_version><space><vendor-specific information>
			string_view ver; char buf[256];
			ver = info(clGetDeviceInfo, device[i][j], CL_DEVICE_VERSION, buf);
			ver = lstrip(ver, "OpenCL ");
			ver = split(ver, ' ').first;
			const auto &[major, minor]
			{
				split(ver, '.')
			};

			api[i][j].major = lex_cast<uint>(major);
			api[i][j].minor = lex_cast<uint>(minor);
		}
		catch(const error &e)
		{
			log::error
			{
				log, "OpenCL [%u][%u] CL_DEVICE_VERSION :%s",
				i, j,
				e.what(),
			};
		}

	return devices_total;
}

size_t
ircd::cl::init::init_ctxs()
{
	// Gather all devices we'll use.
	size_t _devs {0};
	cl_device_id _dev[DEVICE_MAX];
	for(size_t i(0); i < platforms; ++i)
		for(size_t j(0); j < devices[i]; ++j)
			_dev[_devs++] = device[i][j];

	// Create a context from gathered devices.
	cl_int err {CL_SUCCESS};
	cl_context_properties ctxprop {0};
	primary = clCreateContext(&ctxprop, _devs, _dev, handle_notify, nullptr, &err);
	throw_on_error(err);

	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

	// Setup legacy queue properties
	cl_command_queue_properties legacy_qprop {0};
	legacy_qprop |= (profile_queue? CL_QUEUE_PROFILING_ENABLE: cl_command_queue_properties{0});
	//legacy_qprop |= CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE;

	// Setup modern queue properties
	cl_queue_properties qprop {0};
	qprop |= (profile_queue? CL_QUEUE_PROFILING_ENABLE: cl_queue_properties{0});
	//qprop |= CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE;
	//qprop |= CL_QUEUE_ON_DEVICE;
	//qprop |= CL_QUEUE_ON_DEVICE_DEFAULT;

	// Create a queue for each device.
	for(size_t i(0); i < platforms; ++i)
		for(size_t j(0); j < devices[i]; ++j)
		{
			queue[i][j] = profile_queue?
				clCreateCommandQueue(primary, device[i][j], legacy_qprop, &err):
				clCreateCommandQueueWithProperties(primary, device[i][j], &qprop, &err);
				//clCreateCommandQueue(primary, device[i][j], legacy_qprop, &err);

			throw_on_error(err);
		}

	// For any inits in the work subsystem.
	work::init();

	#pragma GCC diagnostic pop
	return _devs;
}

void
ircd::cl::init::fini_ctxs()
{
	if(primary)
		work::fini();

	for(size_t i(0); i < PLATFORM_MAX; ++i)
		for(size_t j(0); j < DEVICE_MAX; ++j)
			if(queue[i][j])
			{
				call(clReleaseCommandQueue, queue[i][j]);
				queue[i][j] = nullptr;
			}

	if(primary)
	{
		call(clReleaseContext, primary);
		primary = nullptr;
	}
}

void
ircd::cl::log_platform_info()
{
	for(size_t i(0); i < platforms; ++i)
		log_platform_info(i);
}

void
ircd::cl::log_platform_info(const uint i)
{
	char buf[3][64];
	char extbuf[320];
	log::logf
	{
		log, log::level::DEBUG,
		"OpenCL [%u][*] %-3d :%s :%s :%s :%s",
		i,
		CL_TARGET_OPENCL_VERSION,
		info(clGetPlatformInfo, platform[i], CL_PLATFORM_VERSION, buf[0]),
		info(clGetPlatformInfo, platform[i], CL_PLATFORM_VENDOR, buf[1]),
		info(clGetPlatformInfo, platform[i], CL_PLATFORM_NAME, buf[2]),
		info(clGetPlatformInfo, platform[i], CL_PLATFORM_EXTENSIONS, extbuf),
	};
}

void
ircd::cl::log_dev_info()
{
	for(size_t i(0); i < platforms; ++i)
		log_dev_info(i);
}

void
ircd::cl::log_dev_info(const uint i)
{
	if(unlikely(i >= PLATFORM_MAX))
		throw std::out_of_range
		{
			"Invalid platform identifier."
		};

	for(size_t j(0); j < devices[i]; ++j)
		log_dev_info(i, j);
}

void
ircd::cl::log_dev_info(const uint i,
                       const uint j)
{
	if(unlikely(i >= PLATFORM_MAX || j >= DEVICE_MAX))
		throw std::out_of_range
		{
			"Invalid platform or device identifier."
		};

	const auto &dev
	{
		device[i][j]
	};

	char buf[12][192];
	char pbuf[8][64];

	const auto type
	{
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_TYPE, buf[0])
	};

	const auto type_str
	{
		type & CL_DEVICE_TYPE_CPU?
			"CPU"_sv:
		type & CL_DEVICE_TYPE_GPU?
			"GPU"_sv:
		type & CL_DEVICE_TYPE_ACCELERATOR?
			"APU"_sv:
			"DEV"_sv
	};

	const fmt::bsprintf<32> head
	{
		"%s id:%u:%u",
		type_str,
		i,
		j,
	};

	log::info
	{
		log, "%s OpenCL cl:%03d clc:%03u dev:%03u :%s :%s :%s :%s",
		string_view{head},
		CL_TARGET_OPENCL_VERSION,
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_OPENCL_C_NUMERIC_VERSION_KHR, buf[0]),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_NUMERIC_VERSION, buf[1]),
		info(clGetDeviceInfo, dev, CL_DEVICE_VERSION, buf[2]),
		info(clGetDeviceInfo, dev, CL_DRIVER_VERSION, buf[3]),
		info(clGetDeviceInfo, dev, CL_DEVICE_VENDOR, buf[4]),
		info(clGetDeviceInfo, dev, CL_DEVICE_NAME, buf[5]),
	};

	const auto wid
	{
		info<std::array<size_t, 3>>(clGetDeviceInfo, dev, CL_DEVICE_MAX_WORK_ITEM_SIZES, buf[0])
	};

	log::info
	{
		log, "%s %u$mHz unit %u[%lu:%lu]%d dims %u[%u:%u:%u]",
		string_view{head},
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_MAX_CLOCK_FREQUENCY, buf[0]),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_MAX_COMPUTE_UNITS, buf[1]),
		primary? query_warp_size(primary, dev): 0UL,
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_MAX_WORK_GROUP_SIZE, buf[2]),
		info<int>(clGetDeviceInfo, dev, CL_DEVICE_PARTITION_PROPERTIES, buf[3]),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_MAX_WORK_ITEM_DIMENSIONS, buf[4]),
		wid[0], wid[1], wid[2],
	};

	log::info
	{
		log, "%s %u$bit-%s %s line %s align %s page %s alloc %s",
		string_view{head},
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_ADDRESS_BITS, buf[0]),
		info<bool>(clGetDeviceInfo, dev, CL_DEVICE_ENDIAN_LITTLE, buf[1])?
			"LE"_sv: "BE"_sv,
		info<bool>(clGetDeviceInfo, dev, CL_DEVICE_ERROR_CORRECTION_SUPPORT, buf[2])?
			"ECC"_sv: "non-ECC"_sv,
		pretty(pbuf[0], iec(info<uint>(clGetDeviceInfo, dev, CL_DEVICE_GLOBAL_MEM_CACHELINE_SIZE, buf[3]))),
		pretty(pbuf[1], iec(info<uint>(clGetDeviceInfo, dev, CL_DEVICE_MIN_DATA_TYPE_ALIGN_SIZE, buf[4]))),
		pretty(pbuf[2], iec(info<uint>(clGetDeviceInfo, dev, CL_DEVICE_MEM_BASE_ADDR_ALIGN, buf[5]))),
		pretty(pbuf[3], iec(info<ulong>(clGetDeviceInfo, dev, CL_DEVICE_MAX_MEM_ALLOC_SIZE, buf[6]))),
	};

	log::info
	{
		log, "%s global %s cache %s type[%02x] banks %u chans %u; local %s type[%02x] banks %u; const %s",
		string_view{head},
		pretty(pbuf[0], iec(info<ulong>(clGetDeviceInfo, dev, CL_DEVICE_GLOBAL_MEM_SIZE, buf[0]))),
		pretty(pbuf[1], iec(info<ulong>(clGetDeviceInfo, dev, CL_DEVICE_GLOBAL_MEM_CACHE_SIZE, buf[1]))),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_GLOBAL_MEM_CACHE_TYPE, buf[2]),
		info<uint, CL_INVALID_VALUE>(clGetDeviceInfo, dev, CL_DEVICE_GLOBAL_MEM_CHANNEL_BANKS_AMD, buf[3], 0U),
		info<uint, CL_INVALID_VALUE>(clGetDeviceInfo, dev, CL_DEVICE_GLOBAL_MEM_CHANNELS_AMD, buf[4], 0U),
		pretty(pbuf[2], iec(info<ulong>(clGetDeviceInfo, dev, CL_DEVICE_LOCAL_MEM_SIZE, buf[5]))),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_LOCAL_MEM_TYPE, buf[6]),
		info<uint, CL_INVALID_VALUE>(clGetDeviceInfo, dev, CL_DEVICE_LOCAL_MEM_BANKS_AMD, buf[7], 0U),
		pretty(pbuf[3], iec(info<ulong>(clGetDeviceInfo, dev, CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, buf[8]))),
	};

	log::logf
	{
		log, log::level::DEBUG,
		"%s char%u short%u half%u int%u float%u long%u double%u; argc:%u cargc:%u",
		string_view{head},
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_NATIVE_VECTOR_WIDTH_CHAR, buf[0]),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_NATIVE_VECTOR_WIDTH_SHORT, buf[1]),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_NATIVE_VECTOR_WIDTH_HALF, buf[2]),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_NATIVE_VECTOR_WIDTH_INT, buf[3]),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_NATIVE_VECTOR_WIDTH_FLOAT, buf[4]),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_NATIVE_VECTOR_WIDTH_LONG, buf[5]),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_NATIVE_VECTOR_WIDTH_DOUBLE, buf[6]),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_MAX_PARAMETER_SIZE, buf[7]),
		info<uint>(clGetDeviceInfo, dev, CL_DEVICE_MAX_CONSTANT_ARGS, buf[8]),
	};

	const bool native_kernel
	(
		CL_EXEC_NATIVE_KERNEL
		& info<ulong>(clGetDeviceInfo, dev, CL_DEVICE_EXECUTION_CAPABILITIES, buf[0])
	);

	const auto il_version
	(
		native_kernel?
			info<uint>(clGetDeviceInfo, dev, CL_DEVICE_IL_VERSION, buf[1]): 0
	);

	log::logf
	{
		log, log::level::DEBUG,
		"%s SPIR-V:%b:%u printf:%lu :%s",
		string_view{head},
		native_kernel,
		il_version,
		info<size_t>(clGetDeviceInfo, dev, CL_DEVICE_PRINTF_BUFFER_SIZE, buf[2]),
		info(clGetDeviceInfo, dev, CL_DEVICE_OPENCL_C_VERSION, buf[3])
	};

	char extensions_buf[2048];
	const string_view extensions
	{
		info(clGetDeviceInfo, dev, CL_DEVICE_EXTENSIONS, extensions_buf)
	};

	log::logf
	{
		log, log::level::DEBUG,
		"%s :%s",
		string_view{head},
		extensions,
	};
}

/// Silly quirks of OpenCL force us to setup a context, compile a program, and
/// instantiate a kernel to find out the warp/wavefront size characteristic.
/// Note that other thread-grouping characteristics are available from device
/// properties directly.
uint
ircd::cl::query_warp_size(cl_context context,
                          cl_device_id device)
{
	//TODO: XXX
	assert(primary);
	assert(context == primary);

	cl::code code
	{
		"__kernel void ircd_test() {}"
	};

	code.compile();
	code.link();

	cl::kern kern
	{
		code, "ircd_test"
	};

	return kern.preferred_group_size_multiple(device);
}

//
// interface
//

void
ircd::cl::sync()
{
	if(unlikely(!primary))
		return;

	auto &q
	{
		queue[0][0]
	};

	call
	(
		clFinish, q
	);

	++primary_stats.sync_count;
}

void
ircd::cl::flush()
{
	auto &q
	{
		queue[0][0]
	};

	call
	(
		clFlush, q
	);

	++primary_stats.flush_count;
}

//
// exec
//

namespace ircd::cl
{
	static const size_t _deps_list_max {32};
	static thread_local cl_event _deps_list[_deps_list_max];

	static void check_submit_blocking(cl::exec *const &, const exec::opts &);
	static void handle_submitted(cl::exec *const &, const exec::opts &);
	static vector_view<cl_event> make_deps_default(cl::work *const &, const exec::opts &);
	static vector_view<cl_event> make_deps(cl::work *const &, const exec::opts &);
}

template<>
decltype(ircd::util::instance_list<ircd::cl::work>::allocator)
ircd::util::instance_list<ircd::cl::work>::allocator
{};

template<>
decltype(ircd::util::instance_list<ircd::cl::work>::list)
ircd::util::instance_list<ircd::cl::work>::list
{
    allocator
};

decltype(ircd::cl::exec::opts_default)
ircd::cl::exec::opts_default;

ircd::cl::exec::exec(const opts &opts)
try
{
	auto &q
	{
		queue[0][0]
	};

	const auto deps
	{
		make_deps(this, opts)
	};

	assert(!this->handle);
	call
	(
		clEnqueueBarrierWithWaitList,
		q,
		deps.size(),
		deps.size()? deps.data(): nullptr,
		reinterpret_cast<cl_event *>(&this->handle)
	);

	primary_stats.exec_barrier_tasks += 1;
	handle_submitted(this, opts);
}
catch(const std::exception &e)
{
	log::error
	{
		log, "Exec Barrier :%s",
		e.what(),
	};

	throw;
}

ircd::cl::exec::exec(kern &kern,
                     const kern::range &work,
                     const opts &opts)
try
{
	size_t dim(0);
	for(size_t i(0); i < work.global.size(); ++i)
		dim += work.global[i] > 0 && dim == i;

	if(!dim)
		return;

	if(unlikely(run::level != run::level::RUN))
		throw unavailable
		{
			"Unable to submit work items in runlevel %s",
			reflect(run::level),
		};

	assert(run::level == run::level::RUN);
	auto &q
	{
		queue[0][0]
	};

	const auto deps
	{
		make_deps(this, opts)
	};

	assert(!this->object);
	this->object = &kern;

	assert(!this->handle);
	call
	(
		clEnqueueNDRangeKernel,
		q,
		cl_kernel(kern.handle),
		dim,
		work.offset.data(),
		work.global.data(),
		work.local.data(),
		deps.size(),
		deps.size()? deps.data(): nullptr,
		reinterpret_cast<cl_event *>(&this->handle)
	);

	size_t global_size(work.global[0]);
	for(size_t i(1); i < dim; ++i)
		global_size *= work.global[i];

	size_t local_size(work.local[0]);
	for(size_t i(1); i < dim; ++i)
		local_size *= work.local[i];

	primary_stats.exec_kern_tasks += 1;
	primary_stats.exec_kern_threads += global_size;
	primary_stats.exec_kern_groups += global_size / local_size;
	handle_submitted(this, opts);
}
catch(const std::exception &e)
{
	log::error
	{
		log, "Exec Kern :%s",
		e.what(),
	};

	throw;
}

ircd::cl::exec::exec(data &dst,
                     const data &src,
                     const opts &opts)
try
{
	auto &q
	{
		queue[0][0]
	};

	assert(src.handle);
	assert(dst.handle);
	const size_t size
	{
		opts.size == -1UL?
			std::min(dst.size(), src.size()):
			opts.size
	};

	if(!size)
		return;

	assert(!this->object);
	this->object = &dst;

	const auto deps
	{
		make_deps(this, opts)
	};

	assert(!this->handle);
	call
	(
		clEnqueueCopyBuffer,
		q,
		cl_mem(src.handle),
		cl_mem(dst.handle),
		opts.offset[1],
		opts.offset[0],
		size,
		deps.size(),
		deps.size()? deps.data(): nullptr,
		reinterpret_cast<cl_event *>(&this->handle)
	);

	primary_stats.exec_copy_bytes += size;
	primary_stats.exec_copy_tasks += 1;
	handle_submitted(this, opts);
}
catch(const std::exception &e)
{
	log::error
	{
		log, "Exec Copy :%s",
		e.what(),
	};

	throw;
}

ircd::cl::exec::exec(data &data,
                     const mutable_buffer &buf,
                     const opts &opts)
try
{
	auto &q
	{
		queue[0][0]
	};

	const size_t size
	{
		opts.size == -1UL?
			ircd::size(buf):
			opts.size
	};

	if(!size)
		return;

	assert(!this->object);
	this->object = &data;

	const auto deps
	{
		make_deps(this, opts)
	};

	assert(!this->handle);
	call
	(
		clEnqueueReadBuffer,
		q,
		cl_mem(data.handle),
		opts.blocking,
		opts.offset[0],
		size,
		ircd::data(buf),
		deps.size(),
		deps.size()? deps.data(): nullptr,
		reinterpret_cast<cl_event *>(&this->handle)
	);

	primary_stats.exec_read_bytes += size;
	primary_stats.exec_read_tasks += 1;
	handle_submitted(this, opts);
}
catch(const std::exception &e)
{
	log::error
	{
		log, "Exec Read data:%p cl_mem:%p buf:%p,%zu :%s",
		&data,
		data.handle,
		ircd::data(buf),
		ircd::size(buf),
		e.what(),
	};

	throw;
}

ircd::cl::exec::exec(data &data,
                     const const_buffer &buf,
                     const opts &opts)
try
{
	const size_t size
	{
		opts.size == -1UL?
			ircd::size(buf):
			opts.size
	};

	if(!size)
		return;

	if(unlikely(run::level != run::level::RUN))
		throw unavailable
		{
			"Unable to write to device in runlevel %s",
			reflect(run::level),
		};

	assert(run::level == run::level::RUN);
	auto &q
	{
		queue[0][0]
	};

	assert(!this->object);
	this->object = &data;

	const auto deps
	{
		make_deps(this, opts)
	};

	assert(!this->handle);
	call
	(
		clEnqueueWriteBuffer,
		q,
		cl_mem(data.handle),
		opts.blocking,
		opts.offset[0],
		size,
		mutable_cast(ircd::data(buf)),
		deps.size(),
		deps.size()? deps.data(): nullptr,
		reinterpret_cast<cl_event *>(&this->handle)
	);

	primary_stats.exec_write_bytes += size;
	primary_stats.exec_write_tasks += 1;
	handle_submitted(this, opts);
}
catch(const std::exception &e)
{
	log::error
	{
		log, "Exec Write data:%p cl_mem:%p buf:%p,%zu :%s",
		&data,
		data.handle,
		ircd::data(buf),
		ircd::size(buf),
		e.what(),
	};

	throw;
}

ircd::cl::exec::exec(data &data,
                     const pair<size_t, off_t> &slice,
                     const read_closure &closure,
                     const opts &opts)
try
{
	const auto size
	{
		slice.first?:
		opts.size == -1UL?
			data.size():
			opts.size
	};

	if(!size)
		return;

	const auto offset
	{
		slice.second?:
			opts.offset[0]
	};

	assert(size_t(size) <= data.size());
	assert(size_t(offset) <= data.size());
	auto &q
	{
		queue[0][0]
	};

	assert(!this->object);
	this->object = &data;

	const auto deps
	{
		make_deps(this, opts)
	};

	cl_map_flags flags {0};
	flags |= CL_MAP_READ;

	int err {CL_SUCCESS};
	assert(!this->handle);
	void *const ptr
	{
		clEnqueueMapBuffer
		(
			q,
			cl_mem(data.handle),
			opts.blocking,
			flags,
			offset,
			size,
			deps.size(),
			deps.size()? deps.data(): nullptr,
			reinterpret_cast<cl_event *>(&this->handle),
			&err
		)
	};

	throw_on_error(err);
	primary_stats.exec_read_bytes += size;
	primary_stats.exec_read_tasks += 1;
	handle_submitted(this, opts);
	assert(this->handle);
	assert(ptr);

	// Perform the unmapping on unwind. This is after the mapping event
	// completed and the closure was called below. The unmapping event will
	// replace the event handle for this exec instance until its actual dtor;
	// thus the lifetime of the exec we are constructing actually represents
	// the unmapping event.
	const unwind unmap{[this, &data, &q, &ptr, &opts]
	{
		assert(!this->handle);
		call
		(
			clEnqueueUnmapMemObject,
			q,
			cl_mem(data.handle),
			ptr,
			0, // deps
			nullptr, // depslist
			reinterpret_cast<cl_event *>(&this->handle)
		);

		handle_submitted(this, opts);
	}};

	// After the closure is called below, or throws, or if wait() throws,
	// we free the completed map event here to allow for the unmap event.
	const unwind rehandle{[this]
	{
		assert(this->handle);
		call(clReleaseEvent, cl_event(this->handle));
		this->handle = nullptr;
		this->work::ts = ircd::cycles();
	}};

	// Wait for the mapping to complete before presenting the buffer.
	wait();
	if(likely(closure))
		closure(const_buffer
		{
			reinterpret_cast<const char *>(ptr), size
		});
}
catch(const std::exception &e)
{
	log::error
	{
		log, "Exec Read Closure :%s",
		e.what(),
	};

	throw;
}

ircd::cl::exec::exec(data &data,
                     const pair<size_t, off_t> &slice,
                     const write_closure &closure,
                     const opts &opts)
try
{
	const auto size
	{
		slice.first?:
		opts.size == -1UL?
			data.size():
			opts.size
	};

	if(!size)
		return;

	if(unlikely(run::level != run::level::RUN))
		throw unavailable
		{
			"Unable to write to device in runlevel %s",
			reflect(run::level),
		};

	assert(run::level == run::level::RUN);
	const auto offset
	{
		slice.second?:
			opts.offset[0]
	};

	assert(size_t(size) <= data.size());
	assert(size_t(offset) <= data.size());
	auto &q
	{
		queue[0][0]
	};

	assert(!this->object);
	this->object = &data;

	const auto deps
	{
		make_deps(this, opts)
	};

	cl_map_flags flags {0};
	flags |= opts.duplex || opts.blocking? CL_MAP_WRITE: CL_MAP_WRITE_INVALIDATE_REGION;
	flags |= opts.duplex? CL_MAP_READ: 0;

	int err {CL_SUCCESS};
	assert(!this->handle);
	void *const ptr
	{
		clEnqueueMapBuffer
		(
			q,
			cl_mem(data.handle),
			opts.blocking,
			flags,
			offset,
			size,
			deps.size(),
			deps.size()? deps.data(): nullptr,
			reinterpret_cast<cl_event *>(&this->handle),
			&err
		)
	};

	throw_on_error(err);
	// Account for read operation only when caller maps read/write.
	primary_stats.exec_read_bytes += opts.duplex? size: 0UL;
	primary_stats.exec_read_tasks += opts.duplex;
	handle_submitted(this, opts);
	assert(this->handle);
	assert(ptr);

	const unwind unmap{[this, &data, &q, &ptr, &opts, &size]
	{
		assert(!this->handle);
		call
		(
			clEnqueueUnmapMemObject,
			q,
			cl_mem(data.handle),
			ptr,
			0, // deps
			nullptr, // depslist
			reinterpret_cast<cl_event *>(&this->handle)
		);

		primary_stats.exec_write_bytes += size;
		primary_stats.exec_write_tasks += 1;
		handle_submitted(this, opts);
	}};

	const unwind rehandle{[this]
	{
		assert(this->handle);
		call(clReleaseEvent, cl_event(this->handle));
		this->handle = nullptr;
		this->work::ts = ircd::cycles();
	}};

	wait();
	if(closure)
		closure(mutable_buffer
		{
			reinterpret_cast<char *>(ptr), size
		});
}
catch(const std::exception &e)
{
	log::error
	{
		log, "Exec Write Closure :%s",
		e.what(),
	};

	throw;
}

void
ircd::cl::handle_submitted(cl::exec *const &exec,
                           const exec::opts &opts)
{
	assert(run::level == run::level::RUN || run::level == run::level::QUIT);

	primary_stats.exec_tasks += 1;

	if(opts.flush)
		cl::flush();

	if(opts.sync)
		cl::sync();

	if(likely(!opts.blocking))
		check_submit_blocking(exec, opts);

	if(opts.nice == 0)
		ctx::yield();

	if(opts.nice > 0)
		ctx::sleep(opts.nice * milliseconds(nice_rate));
}

/// Checks if the OpenCL runtime blocked this thread to sound the alarms.
void
ircd::cl::check_submit_blocking(cl::exec *const &exec,
                                const exec::opts &opts)
{
	const uint64_t &threshold
	{
		watchdog_tsc
	};

	if(!threshold)
		return;

	const auto submit_cycles
	{
		prof::cycles() - exec->ts
	};

	if(likely(submit_cycles < threshold))
		return;

	char nbuf[64];
	const auto name
	{
		exec->name(nbuf)
	};

	char pbuf[32];
	log::dwarning
	{
		log, "clEnqueue() kernel '%s' blocking the host for %s cycles on submit.",
		name?: "<unnamed kernel or unknown command type>"_sv,
		pretty(pbuf, si(submit_cycles), 1),
	};
}

ircd::vector_view<cl_event>
ircd::cl::make_deps(cl::work *const &work,
                    const exec::opts &opts)
{
	//TODO: for out-of-order queue
	if((false) && empty(opts.deps) && !opts.indep)
		return make_deps_default(work, opts);

	if(empty(opts.deps))
		return {};

	size_t ret(0);
	vector_view<cl_event> out(_deps_list);
	for(auto &exec : opts.deps)
		out.at(ret++) = cl_event(exec.handle);

	return vector_view<cl_event>
	{
		out, ret
	};
}

ircd::vector_view<cl_event>
ircd::cl::make_deps_default(cl::work *const &work,
                            const exec::opts &opts)
{
	size_t ret(0);
	vector_view<cl_event> out(_deps_list);
	for(auto it(rbegin(cl::work::list)); it != rend(cl::work::list); ++it)
	{
		cl::work *const &other{*it};
		if(other == work)
			continue;

		if(!other->handle)
			continue;

		if(other->context != ctx::current)
			continue;

		out.at(ret++) = cl_event(other->handle);
		break;
	}

	return vector_view<cl_event>
	{
		out, ret
	};
}

//
// kern
//

ircd::cl::kern::kern(code &code,
                     const string_view &name)
try
{
	int err {CL_SUCCESS};
	handle = clCreateKernel(cl_program(code.handle), name.c_str(), &err);
	throw_on_error(err);

	const std::array<size_t, 3> cgs
	{
		#ifdef RB_DEBUG
		compile_group_size()
		#else
		0, 0, 0
		#endif
	};

	char buf[1][16];
	char pbuf[2][48];
	log::debug
	{
		log, "kernel stack %s local %s group:%zu pref:%zu comp:%zu:%zu:%zu :%s",
		pretty(pbuf[0], iec(stack_mem_size())),
		pretty(pbuf[1], iec(local_mem_size())),
		group_size(),
		preferred_group_size_multiple(),
		cgs[0], cgs[1], cgs[2],
		name,
	};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "Kernel Create '%s' :%s",
		name,
		e.what(),
	};

	throw;
}

ircd::cl::kern::kern(kern &&o)
noexcept
:handle{std::move(o.handle)}
{
	o.handle = nullptr;
}

ircd::cl::kern &
ircd::cl::kern::operator=(kern &&o)
noexcept
{
	this->~kern();
	handle = std::move(o.handle);
	o.handle = nullptr;
	return *this;
}

ircd::cl::kern::~kern()
noexcept try
{
	if(likely(handle))
		call(clReleaseKernel, cl_kernel(handle));
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "Kernel Release :%s",
		e.what(),
	};

	return;
}

void
ircd::cl::kern::arg(const int i,
                    data &data)
{
	const auto &data_handle
	{
		cl_mem(data.handle)
	};

	call(clSetKernelArg, cl_kernel(handle), i, sizeof(cl_mem), &data_handle);
}

void
ircd::cl::kern::arg(const int i,
                    const const_buffer &buf)
{
	call(clSetKernelArg, cl_kernel(handle), i, ircd::size(buf), ircd::data(buf));
}

std::array<size_t, 3>
ircd::cl::kern::compile_group_size(void *const dev)
const
{
	char buf[24];
	const auto handle(cl_kernel(this->handle));
	constexpr auto flag(CL_KERNEL_COMPILE_WORK_GROUP_SIZE);
	return info<std::array<size_t, 3>>(clGetKernelWorkGroupInfo, handle, cl_device_id(dev), flag, buf);
}

size_t
ircd::cl::kern::preferred_group_size_multiple(void *const dev)
const
{
	char buf[16];
	const auto handle(cl_kernel(this->handle));
	constexpr auto flag(CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE);
	return info<size_t>(clGetKernelWorkGroupInfo, handle, cl_device_id(dev), flag, buf);
}

size_t
ircd::cl::kern::group_size(void *const dev)
const
{
	char buf[16];
	const auto handle(cl_kernel(this->handle));
	constexpr auto flag(CL_KERNEL_WORK_GROUP_SIZE);
	return info<size_t>(clGetKernelWorkGroupInfo, handle, cl_device_id(dev), flag, buf);
}

size_t
ircd::cl::kern::local_mem_size(void *const dev)
const
{
	char buf[16];
	const auto handle(cl_kernel(this->handle));
	constexpr auto flag(CL_KERNEL_LOCAL_MEM_SIZE);
	return info<ulong>(clGetKernelWorkGroupInfo, handle, cl_device_id(dev), flag, buf);
}

size_t
ircd::cl::kern::stack_mem_size(void *const dev)
const
{
	char buf[16];
	const auto handle(cl_kernel(this->handle));
	constexpr auto flag(CL_KERNEL_PRIVATE_MEM_SIZE);
	return info<ulong>(clGetKernelWorkGroupInfo, handle, cl_device_id(dev), flag, buf);
}

uint
ircd::cl::kern::argc()
const
{
	const auto handle
	{
		cl_kernel(this->handle)
	};

	char buf[sizeof(uint)];
	return info<uint>(clGetKernelInfo, handle, CL_KERNEL_NUM_ARGS, buf);
}

ircd::string_view
ircd::cl::kern::name(const mutable_buffer &buf)
const
{
	const auto handle
	{
		cl_kernel(this->handle)
	};

	return handle?
		info(clGetKernelInfo, handle, CL_KERNEL_FUNCTION_NAME, buf):
		string_view{};
}

//
// code
//

namespace ircd::cl
{
	static void build_handle_error_log_line(const string_view &line);
	static void build_handle_error(code &, const opencl_error &);
	static void build_handle(cl_program program, void *priv);
}

//
// code::code
//

ircd::cl::code::code(const string_view &src)
:code
{
	vector_view<const string_view>(&src, 1),
}
{
}

ircd::cl::code::code(const vector_view<const string_view> &srcs)
{
	static const size_t iov_max
	{
		64 //TODO: ???
	};

	const auto count(srcs.size());
	if(unlikely(count > iov_max))
		throw error
		{
			"Maximum number of sources exceeded: lim:%zu got:%zu",
			iov_max,
			srcs.size(),
		};

	size_t len[count];
	const char *src[count];
	for(size_t i(0); i < count; ++i)
		src[i] = ircd::data(srcs[i]),
		len[i] = ircd::size(srcs[i]);

	char pbuf[1][48];
	log::logf
	{
		log, log::level::DEBUG,
		"code(%p) creating %s srcs:%zu",
		this,
		pretty(pbuf[0], si(std::accumulate(len, len + count, 0))),
		count,
	};

	int err {CL_SUCCESS};
	handle = clCreateProgramWithSource(primary, count, src, len, &err);
	throw_on_error(err);
}

ircd::cl::code::code(const vector_view<const const_buffer> &bins)
{
	static const size_t iov_max
	{
		64 //TODO: ???
	};

	const auto count(bins.size());
	if(unlikely(count > iov_max))
		throw error
		{
			"Maximum number of binaries exceeded: lim:%zu got:%zu",
			iov_max,
			count,
		};

	size_t len[iov_max + 1] {0};
	const uint8_t *bin[iov_max + 1] {nullptr};
	for(size_t i(0); i < count; ++i)
		bin[i] = reinterpret_cast<const uint8_t *>(ircd::data(bins[i])),
		len[i] = ircd::size(bins[i]);

	size_t devs {0};
	cl_device_id dev[DEVICE_MAX] {0};
	for(size_t i(0); i < platforms; ++i)
		for(size_t j(0); j < devices[i]; ++j)
			dev[devs++] = device[i][j];

	char pbuf[1][48];
	log::logf
	{
		log, log::level::DEBUG,
		"code(%p) loading %s bins:%zu devs:%zu",
		this,
		pretty(pbuf[0], si(std::accumulate(len, len + count, 0))),
		count,
		devs,
	};

	assert(len);
	assert(devs);

	int err {CL_SUCCESS};
	int binerr[iov_max + 1] {CL_SUCCESS};
	handle = clCreateProgramWithBinary(primary, devs, dev, len, bin, binerr, &err);
	throw_on_error(err);
	for(size_t i(0); i < count; ++i)
		throw_on_error(binerr[i]);
}

ircd::cl::code::code(code &&o)
noexcept
:handle{std::move(o.handle)}
{
	o.handle = nullptr;
}

ircd::cl::code &
ircd::cl::code::operator=(code &&o)
noexcept
{
	this->~code();
	handle = std::move(o.handle);
	o.handle = nullptr;
	return *this;
}

ircd::cl::code::~code()
noexcept try
{
	if(likely(handle))
		call(clReleaseProgram, cl_program(handle));
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "Program Release :%s",
		e.what(),
	};

	return;
}

void
ircd::cl::code::build(const string_view &opts)
try
{
	const uint num_devices {1};
	const cl_device_id *device_list
	{
		device[0] //TODO: XXX
	};

	log::logf
	{
		log, log::level::DEBUG,
		"code(%p) building devs:%zu %c%s",
		this,
		num_devices,
		opts? ':': ' ',
		opts,
	};

	call
	(
		clBuildProgram,
		cl_program(handle),
		num_devices,
		device_list,
		opts.c_str(),
		cl::build_handle,
		this
	);
}
catch(const opencl_error &e)
{
	build_handle_error(*this, e);
	throw;
}
catch(const std::exception &e)
{
	log::error
	{
		log, "code(%p) :Failed to build :%s",
		this,
		e.what(),
	};

	throw;
}

void
ircd::cl::code::link(const string_view &opts)
try
{
	const uint num_devices {1};
	const cl_device_id *device_list
	{
		device[0] //TODO: XXX
	};

	const uint num_progs {1};
	const cl_program progs[]
	{
		cl_program(handle)
	};

	log::logf
	{
		log, log::level::DEBUG,
		"code(%p) linking devs:%zu progs:%zu %c%s",
		this,
		num_devices,
		num_progs,
		opts? ':': ' ',
		opts,
	};

	int err
	{
		CL_COMPILER_NOT_AVAILABLE
	};

	#ifdef CL_VERSION_1_2
	handle = clLinkProgram
	(
		primary,
		num_devices,
		device_list,
		opts.c_str(),
		num_progs,
		progs,
		cl::build_handle,
		this,
		&err
	);
	#endif

	throw_on_error(err);
}
catch(const opencl_error &e)
{
	build_handle_error(*this, e);
	throw;
}
catch(const std::exception &e)
{
	log::error
	{
		log, "code(%p) :Failed to link :%s",
		this,
		e.what(),
	};

	throw;
}

void
ircd::cl::code::compile(const string_view &opts)
try
{
	const uint num_devices {1};
	const cl_device_id *device_list
	{
		device[0] //TODO: XXX
	};

	const uint num_headers {0};
	const cl_program *header_progs
	{
		nullptr
	};

	const char *header_names[]
	{
		nullptr
	};

	log::logf
	{
		log, log::level::DEBUG,
		"code(%p) compiling devs:%zu headers:%zu %c%s",
		this,
		num_devices,
		num_headers,
		opts? ':': ' ',
		opts,
	};

	#ifdef CL_VERSION_1_2
	call
	(
		clCompileProgram,
		cl_program(handle),
		num_devices,
		device_list,
		opts.c_str(),
		num_headers,
		header_progs,
		nullptr, //header_names, // clover api bug?
		cl::build_handle,
		this
	);
	#else
	throw_on_error(CL_COMPILER_NOT_AVAILABLE);
	#endif
}
catch(const opencl_error &e)
{
	build_handle_error(*this, e);
	throw;
}
catch(const std::exception &e)
{
	log::error
	{
		log, "code(%p) :Failed to compile :%s",
		this,
		e.what(),
	};

	throw;
}

ircd::string_view
ircd::cl::code::src(const mutable_buffer &buf)
const
{
	const auto &handle
	{
		cl_program(this->handle)
	};

	return info(clGetProgramInfo, handle, CL_PROGRAM_SOURCE, buf);
}

ircd::vector_view<const ircd::mutable_buffer>
ircd::cl::code::bin(vector_view<mutable_buffer> buf)
const
{
	const auto &handle
	{
		cl_program(this->handle)
	};

	const auto devs
	{
		this->devs()
	};

	assert(devs <= ircd::size(buf));
	const auto count
	{
		std::min(devs, ircd::size(buf))
	};

	size_t bin_sz[count];
	const auto bins
	{
		this->bins({bin_sz, count})
	};

	assert(bins <= count);
	const auto num
	{
		std::min(bins, count)
	};

	for(size_t i(0); i < num; ++i)
		buf[i] = mutable_buffer
		{
			buf[i], bin_sz[i]
		};

	uintptr_t ptr[num];
	for(size_t i(0); i < num; ++i)
		ptr[i] = uintptr_t(ircd::data(buf[i]));

	info(clGetProgramInfo, handle, CL_PROGRAM_BINARIES, mutable_buffer
	{
		reinterpret_cast<char *>(ptr), sizeof(uintptr_t) * num
	});

	return buf;
}

size_t
ircd::cl::code::bins_size()
const
{
	const auto devs
	{
		this->devs()
	};

	size_t bin_sz[devs];
	const auto bins
	{
		this->bins({bin_sz, devs})
	};

	assert(bins <= devs);
	const auto ret
	{
		std::accumulate(bin_sz, bin_sz + bins, 0UL)
	};

	return ret;
}

size_t
ircd::cl::code::bins(const vector_view<size_t> &buf)
const
{
	const auto &handle
	{
		cl_program(this->handle)
	};

	const auto count
	{
		devs()
	};

	assert(count <= size(buf));
	info(clGetProgramInfo, handle, CL_PROGRAM_BINARY_SIZES, mutable_buffer
	{
		reinterpret_cast<char *>(ircd::data(buf)), ircd::size(buf) * sizeof(size_t)
	});

	return count;
}

size_t
ircd::cl::code::devs()
const
{
	char buf[sizeof(uint)];
	const auto &handle
	{
		cl_program(this->handle)
	};

	return info<uint>(clGetProgramInfo, handle, CL_PROGRAM_NUM_DEVICES, buf);
}

long
ircd::cl::code::status()
const
{
	const auto &handle
	{
		cl_program(this->handle)
	};

	cl_build_status buf;
	const mutable_buffer mb
	{
		reinterpret_cast<char *>(&buf), sizeof(buf)
	};

	const auto &dev
	{
		device[0][0], //TODO: XXX
	};

	const auto ret
	{
		info<cl_build_status>(clGetProgramBuildInfo, handle, dev, CL_PROGRAM_BUILD_STATUS, mb)
	};

	return ret;
}

void
ircd::cl::build_handle(cl_program program,
                       void *const priv)
{
	cl::code *const &code
	{
		reinterpret_cast<cl::code *>(priv)
	};

	assert(code);
	char pbuf[1][48];
	log::logf
	{
		log, log::level::DEBUG,
		"program(%p) devs:%zu binsz:%s :Build complete.",
		(const void *)program,
		code->devs(),
		pretty(pbuf[0], si(code->bins_size())),
	};
}

void
ircd::cl::build_handle_error(code &code,
                             const opencl_error &e)
{
	const auto string_closure
	{
		[&code](const mutable_buffer &buf)
		{
			size_t len {0}; call
			(
				clGetProgramBuildInfo,
				cl_program(code.handle),
				device[0][0], //TODO: XXX
				CL_PROGRAM_BUILD_LOG,
				ircd::size(buf),
				ircd::data(buf),
				&len
			);

			return len;
		}
	};

	const auto error_message
	{
		ircd::string(8_KiB | SHRINK_TO_FIT, string_closure)
	};

	const auto lines
	{
		ircd::tokens(error_message, '\n', build_handle_error_log_line)
	};
}

void
ircd::cl::build_handle_error_log_line(const string_view &line)
{
	// note last line is just a CR
	if(line.size() <= 1)
		return;

	const auto &[loc, line_]    { split(line, ' ')   };
	const auto &[fac, msg]      { split(line_, ' ')  };
	const auto &[fname, pos]    { split(loc, ':')    };
	const auto &[row, col]      { split(pos, ':')    };

	const auto level
	{
		startswith(fac, "warning")?
			log::level::WARNING:

		startswith(fac, "error")?
			log::level::ERROR:

		log::level::ERROR
	};

	log::logf
	{
		log, level, "%s", line
	};
}

//
// data
//

decltype(ircd::cl::data::use_host_ptr)
ircd::cl::data::use_host_ptr
{
	{ "name",     "ircd.cl.data.use_host_ptr"           },
	{ "default",  false                                 },
	{ "help",     "Non-buggy platforms can try `true`." },
};

decltype(ircd::cl::data::gart_page_size)
ircd::cl::data::gart_page_size
{
	{ "name",     "ircd.cl.data.gart.page_size"           },
	{ "default",  4096                                    },
	{ "help",     "Override (un)detected gart page size." },
};

ircd::cl::data::data(const size_t size,
                     const bool host_read,
                     const bool host_write)
{
	if(!size)
		return;

	cl_mem_flags flags {0};
	flags |= CL_MEM_READ_WRITE;
	flags |= host_read && !host_write? CL_MEM_HOST_READ_ONLY: 0;
	flags |= !host_read && host_write? CL_MEM_HOST_WRITE_ONLY: 0;
	flags |= !host_read && !host_write? CL_MEM_HOST_NO_ACCESS: 0;

	int err {CL_SUCCESS};
	handle = clCreateBuffer
	(
		primary,
		flags,
		size,
		nullptr,
		&err
	);

	throw_on_error(err);
	primary_stats.alloc_count += 1;
	primary_stats.alloc_bytes += size;
}

ircd::cl::data::data(const mutable_buffer &buf,
                     const bool wonly)
{
	const auto &ptr
	{
		ircd::data(buf)
	};

	const auto &size
	{
		ptr?
			ircd::size(buf):
			size_t(std::get<1>(buf))
	};

	if(!size)
		return;

	cl_mem_flags flags {0};
	flags |= wonly? CL_MEM_WRITE_ONLY: CL_MEM_READ_WRITE;
	flags |= ptr && use_host_ptr? CL_MEM_USE_HOST_PTR: 0;

	assert(!ptr || aligned(buf, size_t(gart_page_size)));
	assert(padded(size, size_t(gart_page_size)));

	int err {CL_SUCCESS};
	handle = clCreateBuffer
	(
		primary,
		flags,
		size,
		use_host_ptr? ptr: nullptr,
		&err
	);

	throw_on_error(err);
	primary_stats.alloc_count += 1;
	primary_stats.alloc_bytes += size;
}

ircd::cl::data::data(const const_buffer &buf)
{
	const auto &ptr
	{
		ircd::data(buf)
	};

	const auto &size
	{
		ptr?
			ircd::size(buf):
			size_t(std::get<1>(buf))
	};

	if(!size)
		return;

	cl_mem_flags flags {0};
	flags |= CL_MEM_READ_ONLY;
	flags |= ptr && use_host_ptr? CL_MEM_USE_HOST_PTR: 0;

	assert(!ptr || aligned(buf, size_t(gart_page_size)));
	assert(padded(size, size_t(gart_page_size)));

	int err {CL_SUCCESS};
	handle = clCreateBuffer
	(
		primary,
		flags,
		size,
		use_host_ptr? mutable_cast(ptr): nullptr,
		&err
	);

	throw_on_error(err);
	primary_stats.alloc_count += 1;
	primary_stats.alloc_bytes += size;
}

ircd::cl::data::data(data &master,
                     const pair<size_t, off_t> &slice)
{
	constexpr auto type
	{
		CL_BUFFER_CREATE_TYPE_REGION
	};

	if(!master.handle)
		return;

	cl_buffer_region region {0};
	region.origin = slice.second;
	region.size = slice.first;
	if(!region.size)
		return;

	assert(aligned(region.origin, size_t(gart_page_size)));
	assert(padded(region.size, size_t(gart_page_size)));

	int err {CL_SUCCESS};
	handle = clCreateSubBuffer
	(
		cl_mem(master.handle),
		cl_mem_flags{0},
		type,
		&region,
		&err
	);

	throw_on_error(err);
}

ircd::cl::data::data(data &&o)
noexcept
:handle{std::move(o.handle)}
{
	o.handle = nullptr;
}

ircd::cl::data &
ircd::cl::data::operator=(data &&o)
noexcept
{
	this->~data();
	handle = std::move(o.handle);
	o.handle = nullptr;
	return *this;
}

ircd::cl::data::~data()
noexcept try
{
	if(likely(handle))
	{
		const auto size
		{
			this->size()
		};

		call(clReleaseMemObject, cl_mem(handle));

		primary_stats.dealloc_count += 1;
		primary_stats.dealloc_bytes += size;
	}
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "Memory Release :%s",
		e.what(),
	};

	return;
}

size_t
ircd::cl::data::refs()
const
{
	assert(handle);

	char buf[sizeof(size_t)] {0};
	return info<uint>(clGetMemObjectInfo, cl_mem(mutable_cast(handle)), CL_MEM_REFERENCE_COUNT, buf);
}

size_t
ircd::cl::data::maps()
const
{
	assert(handle);

	char buf[sizeof(size_t)] {0};
	return info<uint>(clGetMemObjectInfo, cl_mem(mutable_cast(handle)), CL_MEM_MAP_COUNT, buf);
}

char *
ircd::cl::data::ptr()
const
{
	assert(handle);

	char buf[sizeof(void *)] {0};
	return info<char *>(clGetMemObjectInfo, cl_mem(mutable_cast(handle)), CL_MEM_HOST_PTR, buf);
}

off_t
ircd::cl::data::offset()
const
{
	assert(handle);

	char buf[sizeof(off_t)] {0};
	return info<off_t>(clGetMemObjectInfo, cl_mem(mutable_cast(handle)), CL_MEM_OFFSET, buf);
}

size_t
ircd::cl::data::size()
const
{
	assert(handle);

	char buf[sizeof(size_t)] {0};
	return info<size_t>(clGetMemObjectInfo, cl_mem(mutable_cast(handle)), CL_MEM_SIZE, buf);
}

uint
ircd::cl::data::flags()
const
{
	assert(handle);

	char buf[sizeof(uint)] {0};
	return info<uint>(clGetMemObjectInfo, cl_mem(mutable_cast(handle)), CL_MEM_FLAGS, buf);
}

//
// cl::work (event)
//

namespace ircd::cl
{
	struct completion;

	extern conf::item<bool> offload_enable;
	extern const ctx::ole::opts offload_opts;

	static void handle_event_callback(cl_event, cl_int, void *) noexcept;
	static int wait_event_callback(work &, const int, const int);
	static int wait_event_offload(work &, const int, const int);
	static int wait_event(work &, const int, const int);
}

struct alignas(64) ircd::cl::completion
{
	cl_event event {nullptr};
	cl_int status {CL_COMPLETE};
	ctx::dock dock;
};

decltype(ircd::cl::offload_enable)
ircd::cl::offload_enable
{
	{ "name",     "ircd.cl.offload.enable"  },
	{ "default",  true                      },
};

decltype(ircd::cl::offload_opts)
ircd::cl::offload_opts
{
	"cl"
};

void
ircd::cl::work::init()
{
}

void
ircd::cl::work::fini()
noexcept
{
	cl::sync();
}

//
// work::work
//

ircd::cl::work::work()
{
	if(unlikely(!cl::linkage))
		throw unavailable
		{
			"OpenCL runtime is not available."
		};

	assert(cl::linkage);
}

ircd::cl::work::work(void *const &handle)
{
	call(clRetainEvent, cl_event(handle));
	this->handle = handle;
}

ircd::cl::work::~work()
noexcept try
{
	if(!handle)
		return;

	const unwind free{[this]
	{
		assert(handle);
		call(clReleaseEvent, cl_event(handle));
	}};

	wait();
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "Work Release :%s",
		e.what(),
	};

	return;
}

void
ircd::cl::work::wait(const uint desired)
try
{
	static_assert(CL_COMPLETE == 0);
	constexpr auto execution_status
	{
		CL_EVENT_COMMAND_EXECUTION_STATUS
	};

	char buf[4];
	int status {0};
	if(likely(handle))
		status = info<int>(clGetEventInfo, cl_event(handle), execution_status, buf);

	if(status > int(desired))
		status = wait_event(*this, status, desired);

	if(unlikely(status < 0))
		throw_on_error(status);

	assert(int(status) == int(desired));
}
catch(const std::exception &e)
{
	log::error
	{
		log, "work(%p)::wait(%u) :%s",
		this,
		desired,
		e.what(),
	};

	throw;
}

ircd::string_view
ircd::cl::work::name(const mutable_buffer &buf)
const
{
	switch(const auto type(this->type()); type)
	{
		default:
			return nullptr;

		case CL_COMMAND_READ_BUFFER:          return "READ_BUFFER";
		case CL_COMMAND_WRITE_BUFFER:         return "WRITE_BUFFER";
		case CL_COMMAND_COPY_BUFFER:          return "COPY_BUFFER";
		case CL_COMMAND_MAP_BUFFER:           return "MAP_BUFFER";
		case CL_COMMAND_UNMAP_MEM_OBJECT:     return "UNMAP_MEM_OBJECT";
		case CL_COMMAND_NDRANGE_KERNEL:
		{
			const auto kern
			{
				reinterpret_cast<const cl::kern *>(object)
			};

			return kern? kern->name(buf): "NDRANGE_KERNEL";
		}
	};
}

int
ircd::cl::work::type()
const
{
	const auto handle
	{
		cl_event(this->handle)
	};

	if(!handle)
		return 0;

	char buf[4];
	return info<int>(clGetEventInfo, handle, CL_EVENT_COMMAND_TYPE, buf);
}

//
// cl::work::prof
//

ircd::cl::work::prof::prof(const cl::work &w)
{
	const auto h
	{
		cl_event(w.handle)
	};

	if(!profile_queue || !h)
	{
		for(uint i(0); i < this->size(); ++i)
			(*this)[i] = 0ns;

		return;
	}

	char b[5][8];
	(*this)[0] = info<nanoseconds>(clGetEventProfilingInfo, h, CL_PROFILING_COMMAND_QUEUED, b[0]);
	(*this)[1] = info<nanoseconds>(clGetEventProfilingInfo, h, CL_PROFILING_COMMAND_SUBMIT, b[1]);
	(*this)[2] = info<nanoseconds>(clGetEventProfilingInfo, h, CL_PROFILING_COMMAND_START, b[2]);
	(*this)[3] = info<nanoseconds>(clGetEventProfilingInfo, h, CL_PROFILING_COMMAND_END, b[3]);
	(*this)[4] = info<nanoseconds>(clGetEventProfilingInfo, h, CL_PROFILING_COMMAND_COMPLETE, b[4]);
}

//
// cl::work (internal)
//

int
ircd::cl::wait_event(work &work,
                     const int status,
                     const int desired)
{
	assert(work.handle);
	assert(status > desired);
	const ctx::uninterruptible::nothrow ui;

	const bool use_offload
	{
		// conf item
		bool(offload_enable)
	};

	const auto ret
	{
		use_offload?
			wait_event_offload(work, status, desired):
			wait_event_callback(work, status, desired)
	};

	const bool is_err
	{
		ret < 0
	};

	const bool is_complete
	{
		ret == CL_COMPLETE
	};

	primary_stats.work_completes += is_complete;
	primary_stats.work_errors += is_err;
	primary_stats.work_waits += 1;
	return ret;
}

int
ircd::cl::wait_event_offload(work &work,
                             const int status,
                             const int desired)
{
	completion c
	{
		cl_event(work.handle),
		status,
	};

	ctx::ole::offload
	{
		offload_opts, [&c]
		{
			assert(c.status != CL_COMPLETE);
			call(clWaitForEvents, 1UL, &c.event);
			c.status = CL_COMPLETE;
		}
	};

	//char buf[4];
	//c.status = info<int>(clGetEventInfo, c.event, CL_EVENT_COMMAND_EXECUTION_STATUS, buf);

	assert(c.status == CL_COMPLETE);
	return c.status;
}

int
ircd::cl::wait_event_callback(work &work,
                              const int status,
                              const int desired)
{
	// Completion state structure on this ircd::ctx's stack.
	completion c
	{
		cl_event(work.handle),
		status,
	};

	// Completion condition closure to be satisfied.
	const auto condition{[&c, &desired]() -> bool
	{
		return !c.event || c.status <= desired;
	}};

	// Register callback with OpenCL; note that the callback might be
	// dispatched immediately from this call itself (see below).
	call
	(
		clSetEventCallback,
		c.event,
		desired,
		&handle_event_callback,
		&c
	);

	// This stats item counts clSetEventCallback()'s which return before OpenCL
	// calls the callback, verifying asynchronicity. If this stats item remains
	// zero, the OpenCL runtime has hijacked our thread for a blocking wait.
	primary_stats.work_waits_async += !condition();

	// Yield ircd::ctx while condition unsatisfied
	c.dock.wait(condition);
	return c.status;
}

void
ircd::cl::handle_event_callback(cl_event event,
                                cl_int status,
                                void *const priv)
noexcept
{
	auto *const c
	{
		reinterpret_cast<completion *>(priv)
	};

	assert(priv != nullptr);
	assert(event != nullptr);
	assert(c->event == event);
	c->status = status;
	c->dock.notify_one();
}

//
// callback surface
//

void
ircd::cl::handle_notify(const char *errstr,
                        const void *token,
                        size_t cb,
                        void *priv)
noexcept
{
	if(errstr)
		log::error
		{
			log, "OpenCL t:%p cb:%zu :%s",
			token,
			cb,
			errstr,
		};
}

//
// util
//

template<class T,
         int maybe,
         class F,
         class id0,
         class param>
T
ircd::cl::info(F&& func,
               const id0 &i0,
               const param &p,
               const mutable_buffer &out,
               T default_)
{
	using ircd::data;
	using ircd::size;

	size_t len {0};
	const auto code
	{
		call<maybe>(std::forward<F>(func), i0, p, size(out), data(out), &len)
	};

	assert(code == CL_SUCCESS || code == maybe);
	if constexpr(maybe != CL_SUCCESS)
		if(code == maybe)
			return default_;

	return byte_view<T>
	{
		string_view
		{
			data(out), len
		}
	};
}

template<class T,
         int maybe,
         class F,
         class id0,
         class id1,
         class param>
T
ircd::cl::info(F&& func,
               const id0 &i0,
               const id1 &i1,
               const param &p,
               const mutable_buffer &out,
               T default_)
{
	using ircd::data;
	using ircd::size;

	size_t len {0};
	const auto code
	{
		call<maybe>(std::forward<F>(func), i0, i1, p, size(out), data(out), &len)
	};

	assert(code == CL_SUCCESS || code == maybe);
	if constexpr(maybe != CL_SUCCESS)
		if(code == maybe)
			return default_;

	return byte_view<T>
	{
		string_view
		{
			data(out), len
		}
	};
}

template<int maybe,
         class func,
         class... args>
int
ircd::cl::call(func&& f,
               args&&... a)
{
	const int ret
	{
		f(std::forward<args>(a)...)
	};

	if constexpr(maybe != CL_SUCCESS)
		if(ret == maybe)
			return ret;

	return throw_on_error(ret);
}

int
ircd::cl::throw_on_error(const int &code)
{
	if(unlikely(is_error(code)))
		throw opencl_error
		{
			"(%d) :%s",
			code,
			reflect_error(code),
		};

	return code;
}

bool
ircd::cl::is_error(const int &code)
noexcept
{
	return code < 0;
}

ircd::string_view
ircd::cl::reflect_error(const int code)
noexcept
{
	switch(code)
	{
		case CL_SUCCESS:                           return "SUCCESS";
		case CL_DEVICE_NOT_FOUND:                  return "DEVICE_NOT_FOUND";
		case CL_DEVICE_NOT_AVAILABLE:              return "DEVICE_NOT_AVAILABLE";
		case CL_COMPILER_NOT_AVAILABLE:            return "COMPILER_NOT_AVAILABLE";
		case CL_MEM_OBJECT_ALLOCATION_FAILURE:     return "MEM_OBJECT_ALLOCATION_FAILURE";
		case CL_OUT_OF_RESOURCES:                  return "OUT_OF_RESOURCES";
		case CL_OUT_OF_HOST_MEMORY:                return "OUT_OF_HOST_MEMORY";
		case CL_PROFILING_INFO_NOT_AVAILABLE:      return "PROFILING_INFO_NOT_AVAILABLE";
		case CL_MEM_COPY_OVERLAP:                  return "MEM_COPY_OVERLAP";
		case CL_IMAGE_FORMAT_MISMATCH:             return "IMAGE_FORMAT_MISMATCH";
		case CL_IMAGE_FORMAT_NOT_SUPPORTED:        return "IMAGE_FORMAT_NOT_SUPPORTED";
		case CL_BUILD_PROGRAM_FAILURE:             return "BUILD_PROGRAM_FAILURE";
		case CL_MAP_FAILURE:                       return "MAP_FAILURE";
		case CL_INVALID_VALUE:                     return "INVALID_VALUE";
		case CL_INVALID_DEVICE_TYPE:               return "INVALID_DEVICE_TYPE";
		case CL_INVALID_PLATFORM:                  return "INVALID_PLATFORM";
		case CL_INVALID_DEVICE:                    return "INVALID_DEVICE";
		case CL_INVALID_CONTEXT:                   return "INVALID_CONTEXT";
		case CL_INVALID_QUEUE_PROPERTIES:          return "INVALID_QUEUE_PROPERTIES";
		case CL_INVALID_COMMAND_QUEUE:             return "INVALID_COMMAND_QUEUE";
		case CL_INVALID_HOST_PTR:                  return "INVALID_HOST_PTR";
		case CL_INVALID_MEM_OBJECT:                return "INVALID_MEM_OBJECT";
		case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR:   return "INVALID_IMAGE_FORMAT_DESCRIPTOR";
		case CL_INVALID_IMAGE_SIZE:                return "INVALID_IMAGE_SIZE";
		case CL_INVALID_SAMPLER:                   return "INVALID_SAMPLER";
		case CL_INVALID_BINARY:                    return "INVALID_BINARY";
		case CL_INVALID_BUILD_OPTIONS:             return "INVALID_BUILD_OPTIONS";
		case CL_INVALID_PROGRAM:                   return "INVALID_PROGRAM";
		case CL_INVALID_PROGRAM_EXECUTABLE:        return "INVALID_PROGRAM_EXECUTABLE";
		case CL_INVALID_KERNEL_NAME:               return "INVALID_KERNEL_NAME";
		case CL_INVALID_KERNEL_DEFINITION:         return "INVALID_KERNEL_DEFINITION";
		case CL_INVALID_KERNEL:                    return "INVALID_KERNEL";
		case CL_INVALID_ARG_INDEX:                 return "INVALID_ARG_INDEX";
		case CL_INVALID_ARG_VALUE:                 return "INVALID_ARG_VALUE";
		case CL_INVALID_ARG_SIZE:                  return "INVALID_ARG_SIZE";
		case CL_INVALID_KERNEL_ARGS:               return "INVALID_KERNEL_ARGS";
		case CL_INVALID_WORK_DIMENSION:            return "INVALID_WORK_DIMENSION";
		case CL_INVALID_WORK_GROUP_SIZE:           return "INVALID_WORK_GROUP_SIZE";
		case CL_INVALID_WORK_ITEM_SIZE:            return "INVALID_WORK_ITEM_SIZE";
		case CL_INVALID_GLOBAL_OFFSET:             return "INVALID_GLOBAL_OFFSET";
		case CL_INVALID_EVENT_WAIT_LIST:           return "INVALID_EVENT_WAIT_LIST";
		case CL_INVALID_EVENT:                     return "INVALID_EVENT";
		case CL_INVALID_OPERATION:                 return "INVALID_OPERATION";
		case CL_INVALID_GL_OBJECT:                 return "INVALID_GL_OBJECT";
		case CL_INVALID_BUFFER_SIZE:               return "INVALID_BUFFER_SIZE";
		case CL_INVALID_MIP_LEVEL:                 return "INVALID_MIP_LEVEL";
		case CL_INVALID_GLOBAL_WORK_SIZE:          return "INVALID_GLOBAL_WORK_SIZE";

		#ifdef CL_VERSION_1_1
		case CL_INVALID_PROPERTY:                  return "INVALID_PROPERTY";
		case CL_MISALIGNED_SUB_BUFFER_OFFSET:      return "MISALIGNED_SUB_BUFFER_OFFSET";
		case CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST: return "EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST";
		#endif

		#ifdef CL_VERSION_1_2
		case CL_COMPILE_PROGRAM_FAILURE:           return "COMPILE_PROGRAM_FAILURE";
		case CL_LINKER_NOT_AVAILABLE:              return "LINKER_NOT_AVAILABLE";
		case CL_LINK_PROGRAM_FAILURE:              return "LINK_PROGRAM_FAILURE";
		case CL_DEVICE_PARTITION_FAILED:           return "DEVICE_PARTITION_FAILED";
		case CL_KERNEL_ARG_INFO_NOT_AVAILABLE:     return "KERNEL_ARG_INFO_NOT_AVAILABLE";
		case CL_INVALID_IMAGE_DESCRIPTOR:          return "INVALID_IMAGE_DESCRIPTOR";
		case CL_INVALID_COMPILER_OPTIONS:          return "INVALID_COMPILER_OPTIONS";
		case CL_INVALID_LINKER_OPTIONS:            return "INVALID_LINKER_OPTIONS";
		case CL_INVALID_DEVICE_PARTITION_COUNT:    return "INVALID_DEVICE_PARTITION_COUNT";
		#endif

		#ifdef CL_VERSION_2_0
		case CL_INVALID_PIPE_SIZE:                 return "INVALID_PIPE_SIZE";
		case CL_INVALID_DEVICE_QUEUE:              return "INVALID_DEVICE_QUEUE";
		#endif

		#ifdef CL_VERSION_2_2
		case CL_INVALID_SPEC_ID:                   return "INVALID_SPEC_ID";
		case CL_MAX_SIZE_RESTRICTION_EXCEEDED:     return "MAX_SIZE_RESTRICTION_EXCEEDED";
		#endif
	}

	return "???????";
}
