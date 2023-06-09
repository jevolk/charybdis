// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#include <ircd/ircd.h>
#include "construct.h"
#include "console.h"

using namespace ircd;

IRCD_EXCEPTION_HIDENAME(ircd::error, bad_command)

decltype(construct::console)
construct::console;

decltype(construct::console::stack_sz)
construct::console::stack_sz
{
	{ "name",     "construct.console.stack.size" },
	{ "default",  long(2_MiB)                    },
};

decltype(construct::console::input_max)
construct::console::input_max
{
	{ "name",     "construct.console.input.max" },
	{ "default",  long(64_KiB)                  },
};

decltype(construct::console::buffer_size)
construct::console::buffer_size
{
	{ "name",     "construct.console.buffer.size" },
	{ "default",  long(96_KiB)                    },
};

decltype(construct::console::ratelimit_sleep)
construct::console::ratelimit_sleep
{
	{ "name",     "construct.console.ratelimit.sleep" },
	{ "default",  75L                                 },
};

decltype(construct::console::ratelimit_bytes)
construct::console::ratelimit_bytes
{
	{ "name",     "construct.console.ratelimit.bytes" },
	{ "default",  long(2_KiB)                         },
};

decltype(construct::console::history_enable)
construct::console::history_enable
{
	{ "name",     "construct.console.history.enable" },
	{ "default",  false                              },
};

decltype(construct::console::generic_message)
construct::console::generic_message
{R"(
*** - To end the console session: type exit, or ctrl-d    -> EOF
*** - To shutdown cleanly: type die, or ctrl-\            -> SIGQUIT
*** - To generate a coredump for developers, type ABORT   -> abort()
***)"_sv
};

decltype(construct::console::console_message)
construct::console::console_message
{R"(
***
*** The server is still running in the background. This is the
*** terminal console also available in your !control room.
***)"_sv
};

decltype(construct::console::seen_message)
construct::console::seen_message;

decltype(construct::console::queue)
construct::console::queue;

decltype(construct::console::quit_when_done)
construct::console::quit_when_done;

decltype(construct::console::interactive_when_done)
construct::console::interactive_when_done;

decltype(construct::console::silent)
construct::console::silent;

bool
construct::console::spawn()
{
	if(active())
		return false;

	construct::console = new console;
	return true;
}

bool
construct::console::interrupt()
{
	if(active())
	{
		construct::console->context.interrupt();
		return true;
	}
	else return false;
}

bool
construct::console::terminate()
{
	if(active())
	{
		construct::console->context.terminate();
		return true;
	}
	else return false;
}

bool
construct::console::active()
{
	return construct::console != nullptr;
}

//
// console::console
//

construct::console::console()
:outbuf
{
	size_t(buffer_size)
}
,context
{
	"console",
	stack_sz,
	std::bind(&console::main, this),
	ircd::context::DISPATCH | ircd::context::SLICE_EXEMPT,
}
,runlevel_changed
{
	std::bind(&console::on_runlevel, this, std::placeholders::_1)
}
{
}

void
construct::console::main()
{
	const unwind dtor{[]
	{
		assert(construct::console);
		construct::console->context.detach();
		delete construct::console;
		construct::console = nullptr;
	}};

	ircd::run::barrier<ircd::ctx::terminated>{};
	ircd::module module{"console"};
	this->module = &module;
	loop();
}

void
construct::console::loop()
try
{
	if(next_command())
		if(handle_queued())
			return;

	show_message(); do
	{
		ctx::interruption_point();
		wait_input();
	}
	while(handle_line());
}
catch(const std::exception &e)
{
	std::cout
	<< "\n***"
	<< "\n*** The console session has ended: " << e.what()
	<< "\n***"
	<< std::endl;

	log::debug
	{
		"The console session has ended: %s", e.what()
	};
}
catch(...)
{
	log::debug
	{
		"The console session has terminated."
	};
}

bool
construct::console::handle_queued()
{
	while(handle_line())
		if(!next_command())
			break;

	if(run::level != run::level::RUN)
		return true;

	if(interactive_when_done)
		return false;

	if(!quit_when_done)
		return true;

	static ircd::ios::descriptor descriptor
	{
		"construct.console.quit"
	};

	ircd::dispatch
	{
		descriptor, ios::defer, ircd::quit
	};

	return true;
}

bool
construct::console::handle_line()
try
{
	if(line == "ABORT")
		abort();

	if(line == "TERMINATE")
		std::terminate();

	if(line == "terminate")
		ircd::terminate();

	if(line == "EXIT")
		exit(0);

	if(line == "TRAP")
	{
		ircd::debugtrap();
		return true;
	}

	if(startswith(line, "record"))
		return cmd__record();

	if(startswith(line, "watch"))
		return cmd__watch();

	int ret{-1};
	if(module) switch((ret = handle_line_bymodule()))
	{
		default:  break;
		case 0:   return false;
		case 1:   return true;
	}

	throw bad_command
	{
		"%s", line
	};
}
catch(const std::out_of_range &e)
{
	std::cerr << "missing required arguments. " << std::endl;
	return true;
}
catch(const bad_command &e)
{
	const ircd::string_view what(e.what());

	std::cerr << "\nBad command";
	if(what)
		std::cerr << " :" << what;
	else
		std::cerr << '.';

	std::cerr << std::endl;
	return true;
}
catch(const http::error &e)
{
	log::error
	{
		"%s %s", e.what(), e.content
	};

	return true;
}
catch(const std::exception &e)
{
	log::error
	{
		"%s", e.what()
	};

	return true;
}

int
construct::console::handle_line_bymodule()
{
	using prototype = int (std::ostream &, const string_view &, const string_view &);

	const mods::import<prototype> command
	{
		*module, "console_command"
	};

	// If this string is set, the user wants to log a copy of the output
	// to the file at this path.
	const fs::fd record_fd
	{
		!record_path? fs::fd{-1}: fs::fd
		{
			string_view{record_path}, fs::fd::opts
			{
				.mode = std::ios::out | std::ios::app,
			}
		}
	};

	struct buf
	:std::streambuf
	{
		size_t syncs {0};
		size_t wrote {0};
		string_view cmdline;
		const fs::fd *record_fd {nullptr};

		void record_append(const string_view &str) const
		{
			if(!record_fd || !*record_fd)
				return;

			if(syncs == 0 && this->cmdline)
			{
				// Generate a copy of the command line to give some context
				// to the output following it.
				const std::string cmdline
				{
					"\n> "s + std::string(this->cmdline) + "\n\n"s
				};

				append(*record_fd, string_view(cmdline));
			}

			if(empty(str))
				return;

			append(*record_fd, str);
		}

		int sync() override
		{
			// Console logs are suppressed starting from the first output.
			if(syncs++ == 0)
				ircd::log::console_disable();

			const string_view str
			{
				pbase(), pptr()
			};

			setp(pbase(), epptr());
			record_append(str);

			if(silent)
				return 0;

			std::cout << str;
			wrote += size(str);
			if(wrote >= size_t(ratelimit_bytes))
			{
				std::cout << std::flush;
				ctx::sleep(milliseconds(ratelimit_sleep));
				wrote = 0;
			}

			return 0;
		}

		int overflow(int ch) override
		{
			this->sync();
			return 0;
		}

		buf *setbuf(char *const s, std::streamsize n) override
		{
			setp(s, s + n);
			return this;
		}

		~buf()
		{
			// Console logs are permitted again after the command completes.
			if(syncs)
				ircd::log::console_enable();
		}
	}
	buf;
	buf.cmdline = line;
	buf.record_fd = &record_fd;
	buf.pubsetbuf(data(outbuf), size(outbuf));

	std::ostream out(&buf);
	out.exceptions(out.badbit | out.failbit | out.eofbit);

	int ret;
	static const string_view opts;
	switch((ret = command(out, line, opts)))
	{
		case 0:
		case 1:
		{
			const string_view str
			{
				view(out, outbuf)
			};

			if(!endswith(str, '\n') && !silent)
				std::cout << std::endl;

			return ret;
		}

		// The command was handled but the arguments were bad_command.
		// The module has its own class for a bad_command exception which
		// is a local and separate symbol from the bad_command here so
		// we use this code to translate it.
		case -2: throw bad_command
		{
			view(out, outbuf)
		};

		// Command isn't handled by the module; continue handling here
		default:
			break;
	}

	return ret;
}

bool
construct::console::cmd__record()
{
	const string_view &args
	{
		tokens_after(line, ' ', 0)
	};

	if(empty(args) && empty(record_path))
	{
		std::cout << "Console not currently recorded to any file." << std::endl;
		return true;
	}

	if(empty(args) && !empty(record_path))
	{
		std::cout << "Stopped recording to file `" << record_path << "'" << std::endl;
		record_path = {};
		return true;
	}

	const auto path
	{
		token(args, ' ', 0)
	};

	std::cout << "Recording console to file `" << path << "'" << std::endl;
	record_path = path;
	return true;
}

bool
construct::console::cmd__watch()
{
	const auto delay
	{
		lex_cast<double>(token(this->line, ' ', 1))
	};

	const ircd::milliseconds sleep_time
	{
		long(delay * 1000.0)
	};

	const string_view &line
	{
		tokens_after(this->line, ' ', 1)
	};

	this->line = line; do
	{
		const ircd::ctx::uninterruptible::nothrow ui;

		std::cout << '\n';
		handle_line(); try
		{
			const log::console_quiet quiet(false);
			ctx::interruptible(ctx::cur(), true);
			ctx::interruption_point();
			ctx::sleep(sleep_time);
		}
		catch(const ctx::interrupted &)
		{
			break;
		}
	}
	while(1);

	return true;
}

void
construct::console::wait_input()
{
	line = {}; do
	{
		// Suppression scope ends after the command is entered
		// so the output of the command (if log messages) can be seen.
		const log::console_quiet quiet(false);
		std::cout << "\n> " << std::flush;

		line.resize(size_t(input_max));
		const mutable_buffer buffer
		{
			const_cast<char *>(line.data()), line.size()
		};

		const string_view read
		{
			fs::stdin::readline(buffer)
		};

		line.resize(size(read));

		if(startswith(line, "\x1B"_sv))
			esc_handle();
	}
	while(line.empty());

	if(bool(history_enable))
		history.emplace_back(line);
}

bool
construct::console::esc_handle()
{
	if(startswith(line, "\x1B\x5B"_sv) && size(line) >= 3)
		return esc_handle_bra();

	line = {};
	return true;
}

bool
construct::console::esc_handle_bra()
{
	switch(line[2])
	{
		case 'A': // up-arrow
		{
			if(history.empty())
			{
				line = {};
				return false;
			}

			line = history.front();
			history.pop_front();
			return true;
		}
	}

	line = {};
	return true;
}

bool
construct::console::next_command()
{
	line = {};
	while(!queue.empty() && line.empty())
	{
		line = std::move(queue.front());
		queue.pop_front();
	}

	return !line.empty();
}

void
construct::console::on_runlevel(const enum ircd::run::level &runlevel)
{
	switch(runlevel)
	{
		case ircd::run::level::QUIT:
		case ircd::run::level::HALT:
			terminate();
			break;

		default:
			break;
	}
}

void
construct::console::show_message()
const
{
	// Determine if the user is in -quiet mode or similar so we can skip this
	// output too. Note that the level given here is arbitrary, but if they
	// did suppress it we won't show this message either...
	if(!ircd::log::console_enabled(ircd::log::level::NOTICE))
		return;

	std::call_once(seen_message, []
	{
		std::cout << console_message << generic_message;
	});
}
