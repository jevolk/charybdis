// The Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2020 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#include <RB_INC_SYS_STAT_H
#include <RB_INC_SYS_STATFS_H
#include <RB_INC_SYS_STATVFS_H
#include <boost/filesystem.hpp>

/// Default maximum path string length (for all filesystems & platforms).
decltype(ircd::fs::NAME_MAX_LEN)
ircd::fs::NAME_MAX_LEN
{
	#ifdef NAME_MAX
		NAME_MAX
	#elif defined(_POSIX_NAME_MAX)
		_POSIX_NAME_MAX
	#else
		255
	#endif
};

/// Default maximum path string length (for all filesystems & platforms).
decltype(ircd::fs::PATH_MAX_LEN)
ircd::fs::PATH_MAX_LEN
{
	#ifdef PATH_MAX
		PATH_MAX
	#elif defined(_POSIX_PATH_MAX)
		_POSIX_PATH_MAX
	#else
		4096
	#endif
};

// Convenience scratch buffers for path making.
namespace ircd::fs
{
	thread_local char _name_scratch[NAME_MAX_LEN];
	thread_local char _path_scratch[PATH_MAX_LEN];
}

// External mutable_buffer to the scratch
decltype(ircd::fs::path_scratch)
ircd::fs::path_scratch
{
	_path_scratch
};

// External mutable_buffer to the scratch
decltype(ircd::fs::name_scratch)
ircd::fs::name_scratch
{
	_name_scratch
};

/// e.g. / default=RB_PREFIX
/// env=ircd_fs_base_prefix
decltype(ircd::fs::base::prefix)
ircd::fs::base::prefix
{
	{
		{ "name",        "ircd.fs.base.prefix"       },
		{ "default",     RB_PREFIX                   },
		{ "help",        "directory prefix"          },
	},
	nullptr
};

/// e.g. /usr/bin default=RB_BIN_DIR
/// env=ircd_fs_base_bin
decltype(ircd::fs::base::bin)
ircd::fs::base::bin
{
	{
		{ "name",        "ircd.fs.base.bin"          },
		{ "default",     RB_BIN_DIR                  },
		{ "help",        "binary directory"          },
	},
	nullptr
};

/// e.g. /etc default=RB_CONF_DIR
/// env=$ircd_fs_base_etc env=$CONFIGURATION_DIRECTORY
decltype(ircd::fs::base::etc)
ircd::fs::base::etc
{
	{
		{ "name",        "ircd.fs.base.etc"          },
		{ "default",     RB_CONF_DIR                 },
		{ "help",        "configuration directory"   },
	}, []
	{
		string_view env;
		if((env = getenv("CONFIGURATION_DIRECTORY")))
			etc._value = env;
	}
};

/// e.g. /usr/lib default=RB_LIB_DIR
/// env=$ircd_fs_base_lib
decltype(ircd::fs::base::lib)
ircd::fs::base::lib
{
	{
		{ "name",        "ircd.fs.base.lib"          },
		{ "default",     RB_LIB_DIR                  },
		{ "help",        "library directory"         },
	},
	nullptr
};

/// e.g. /usr/lib/modules/construct default=RB_MODULE_DIR
/// env=$ircd_fs_base_modules
decltype(ircd::fs::base::modules)
ircd::fs::base::modules
{
	{
		{ "name",        "ircd.fs.base.modules"      },
		{ "default",     RB_MODULE_DIR               },
		{ "help",        "modules directory"         },
	},
	nullptr
};

/// e.g. /usr/share/construct default=RB_DATA_DIR
/// env=$ircd_fs_base_share
decltype(ircd::fs::base::share)
ircd::fs::base::share
{
	{
		{ "name",        "ircd.fs.base.share"        },
		{ "default",     RB_DATA_DIR                 },
		{ "help",        "read-only data directory"  },
	},
	nullptr
};

/// e.g. /var/run/construct default=RB_RUN_DIR
/// env=$ircd_fs_base_run env=$RUNTIME_DIRECTORY
decltype(ircd::fs::base::run)
ircd::fs::base::run
{
	{
		{ "name",        "ircd.fs.base.run"          },
		{ "default",     RB_RUN_DIR                  },
		{ "help",        "runtime directory"         },
	}, []
	{
		string_view env;
		if((env = getenv("RUNTIME_DIRECTORY")))
			run._value = env;
	}
};

/// e.g. /var/log/construct default=RB_LOG_DIR
/// env=$ircd_fs_base_log env=$LOGS_DIRECTORY
decltype(ircd::fs::base::log)
ircd::fs::base::log
{
	{
		{ "name",        "ircd.fs.base.log"          },
		{ "default",     RB_LOG_DIR                  },
		{ "help",        "logging directory"         },
	}, []
	{
		string_view env;
		if((env = getenv("LOGS_DIRECTORY")))
			log._value = env;
	}
};

/// e.g. /var/db/construct default=RB_DB_DIR
/// env=$ircd_fs_base_db env=$STATE_DIRECTORY
decltype(ircd::fs::base::db)
ircd::fs::base::db
{
	{
		{ "name",        "ircd.fs.base.db"           },
		{ "default",     RB_DB_DIR                   },
		{ "help",        "database directory"        },
	}, []
	{
		string_view env;
		if((env = getenv("STATE_DIRECTORY")))
			db._value = env;
	}
};

std::string
ircd::fs::cwd()
try
{
	const auto &cur
	{
		filesystem::current_path()
	};

	return cur.string();
}
catch(const filesystem::filesystem_error &e)
{
	throw error{e};
}

ircd::string_view
ircd::fs::cwd(const mutable_buffer &buf)
try
{
	const auto &cur
	{
		filesystem::current_path()
	};

	return strlcpy(buf, cur.native());
}
catch(const filesystem::filesystem_error &e)
{
	throw error{e};
}

#ifdef _PC_PATH_MAX
size_t
ircd::fs::path_max_len(const string_view &path)
{
	return pathconf(path, _PC_PATH_MAX);
}
#else
size_t
ircd::fs::path_max_len(const string_view &path)
{
	return PATH_MAX_LEN;
}
#endif

#ifdef _PC_NAME_MAX
size_t
ircd::fs::name_max_len(const string_view &path)
{
	return pathconf(path, _PC_NAME_MAX);
}
#elif defined(HAVE_SYS_STATFS_H)
size_t
ircd::fs::name_max_len(const string_view &path)
{
	struct statfs f{0};
	syscall(::statfs, path_cstr(path), &f);
	return f.f_namelen;
}
#else
size_t
ircd::fs::name_max_len(const string_view &path)
{
	return NAME_MAX_LEN;
}
#endif

long
ircd::fs::pathconf(const string_view &path,
                   const int &arg)
{
	return syscall(::pathconf, path_cstr(path), arg);
}

ircd::string_view
ircd::fs::filename(const mutable_buffer &buf,
                   const string_view &p)
{
	return path(buf, _path(p).filename());
}

ircd::string_view
ircd::fs::extension(const mutable_buffer &buf,
                    const string_view &p)
{
	return path(buf, _path(p).extension());
}

ircd::string_view
ircd::fs::extension(const mutable_buffer &buf,
                    const string_view &p,
                    const string_view &replace)
{
	return path(buf, _path(p).replace_extension(_path(replace)));
}

ircd::string_view
ircd::fs::relative(const mutable_buffer &buf,
                   const string_view &root,
                   const string_view &p)
{
	return path(buf, relative(_path(p), _path(root)));
}

bool
ircd::fs::is_relative(const string_view &p)
{
	return _path(p).is_relative();
}

bool
ircd::fs::is_absolute(const string_view &p)
{
	return _path(p).is_absolute();
}

//
// fs::path_cstr()
//

namespace ircd::fs
{
	static const size_t _PATH_CSTR_BUFS {4};
	thread_local char _path_cstr[_PATH_CSTR_BUFS][PATH_MAX_LEN];
	thread_local size_t _path_cstr_pos;
}

const char *
ircd::fs::path_cstr(const string_view &s)
{
	const auto pos
	{
		++_path_cstr_pos %= _PATH_CSTR_BUFS
	};

	strlcpy(_path_cstr[pos], s);
	return _path_cstr[pos];
}

//
// fs::path()
//

ircd::string_view
ircd::fs::path(const mutable_buffer &buf,
               const filesystem::path &path)
{
	return strlcpy(buf, path.c_str());
}

ircd::string_view
ircd::fs::path(const mutable_buffer &buf,
               const path_strings &list)
{
	return strlcpy(buf, _path(list).c_str());
}

ircd::string_view
ircd::fs::path(const mutable_buffer &buf,
               const path_views &list)
{
	return strlcpy(buf, _path(list).c_str());
}

//
// fs::_path()
//

boost::filesystem::path
ircd::fs::_path(const path_strings &list)
try
{
	filesystem::path ret;
	for(const auto &s : list)
		ret /= s;

	return ret.string();
}
catch(const filesystem::filesystem_error &e)
{
	throw error{e};
}

boost::filesystem::path
ircd::fs::_path(const path_views &list)
try
{
	filesystem::path ret;
	for(const auto &s : list)
		ret /= _path(s);

	return ret.string();
}
catch(const filesystem::filesystem_error &e)
{
	throw error{e};
}

boost::filesystem::path
ircd::fs::_path(const string_view &s)
try
{
	return _path(std::string{s});
}
catch(const filesystem::filesystem_error &e)
{
	throw error{e};
}

boost::filesystem::path
ircd::fs::_path(std::string s)
try
{
	return filesystem::path{std::move(s)};
}
catch(const filesystem::filesystem_error &e)
{
	throw error{e};
}