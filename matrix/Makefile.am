AUTOMAKE_OPTIONS = foreign

BUILT_SOURCES =#
CLEANFILES =#

DEFS += -DIRCD_UNIT
DEFS += -DIRCD_MATRIX_UNIT

AM_CPPFLAGS =#
AM_CPPFLAGS += -I$(top_srcdir)/include

AM_CXXFLAGS =#

AM_LDFLAGS =#
AM_LDFLAGS += -version-info 0:1:0
AM_LDFLAGS += -Wl,--sort-section=name
AM_LDFLAGS += -Wl,--no-undefined-version
AM_LDFLAGS += -Wl,--allow-shlib-undefined
AM_LDFLAGS += -Wl,--unresolved-symbols=ignore-in-shared-libs
AM_LDFLAGS += -Wl,-Bsymbolic
AM_LDFLAGS += -Wl,-z,lazy
AM_LDFLAGS += -L$(top_srcdir)/ircd
AM_LDFLAGS += $(PLATFORM_LDFLAGS)

if CLANG_PCH
AM_CPPFLAGS += -include-pch $(top_srcdir)/include/ircd/matrix.pic.h.gch
AM_CPPFLAGS += -include ircd/mods/mapi.h
else
AM_CPPFLAGS += -include ircd/matrix.pic.h
AM_CPPFLAGS += -include ircd/mods/mapi.h
endif

if GCC
if GCC13
AM_CXXFLAGS += -ftls-model=global-dynamic
else
AM_CXXFLAGS += -ftls-model=local-dynamic
endif
endif

if LTO
if GCC
AM_CXXFLAGS += -flto=auto
endif
endif

if LTO
if CLANG15 # trouble with ld.gold <= llvm-14
AM_CXXFLAGS += -flto=thin
AM_CXXFLAGS += -fstrict-vtable-pointers
AM_CXXFLAGS += -fwhole-program-vtables
endif
endif

if GOLD
AM_LDFLAGS += -Wl,--no-gnu-unique
AM_LDFLAGS += -Wl,--no-text-reorder
AM_LDFLAGS += -Wl,--sort-common=descending
endif

if MINGW
AM_LDFLAGS += -Wl,--enable-runtime-pseudo-reloc
endif

CXXFLAGS += $(EXTRA_CXXFLAGS)
CPPFLAGS += $(EXTRA_CPPFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)

#
# libircd_matrix
#

libircd_matrixdir = @libdir@
libircd_matrix_LTLIBRARIES =#
libircd_matrix_LTLIBRARIES += libircd_matrix.la

libircd_matrix_la_SOURCES =#
libircd_matrix_la_SOURCES += name.cc
libircd_matrix_la_SOURCES += id.cc
libircd_matrix_la_SOURCES += dbs.cc
libircd_matrix_la_SOURCES += dbs_event_idx.cc
libircd_matrix_la_SOURCES += dbs_event_json.cc
libircd_matrix_la_SOURCES += dbs_event_column.cc
libircd_matrix_la_SOURCES += dbs_event_refs.cc
libircd_matrix_la_SOURCES += dbs_event_horizon.cc
libircd_matrix_la_SOURCES += dbs_event_sender.cc
libircd_matrix_la_SOURCES += dbs_event_type.cc
libircd_matrix_la_SOURCES += dbs_event_state.cc
libircd_matrix_la_SOURCES += dbs_room_events.cc
libircd_matrix_la_SOURCES += dbs_room_type.cc
libircd_matrix_la_SOURCES += dbs_room_state.cc
libircd_matrix_la_SOURCES += dbs_room_state_space.cc
libircd_matrix_la_SOURCES += dbs_room_joined.cc
libircd_matrix_la_SOURCES += dbs_room_head.cc
libircd_matrix_la_SOURCES += dbs_desc.cc
libircd_matrix_la_SOURCES += dbs_init.cc
libircd_matrix_la_SOURCES += hook.cc
libircd_matrix_la_SOURCES += event.cc
libircd_matrix_la_SOURCES += event_cached.cc
libircd_matrix_la_SOURCES += event_conforms.cc
libircd_matrix_la_SOURCES += event_fetch.cc
libircd_matrix_la_SOURCES += event_get.cc
libircd_matrix_la_SOURCES += event_id.cc
libircd_matrix_la_SOURCES += event_index.cc
libircd_matrix_la_SOURCES += event_prefetch.cc
libircd_matrix_la_SOURCES += event_auth.cc
libircd_matrix_la_SOURCES += event_prev.cc
libircd_matrix_la_SOURCES += event_refs.cc
libircd_matrix_la_SOURCES += event_purge.cc
libircd_matrix_la_SOURCES += room.cc
libircd_matrix_la_SOURCES += room_auth.cc
libircd_matrix_la_SOURCES += room_aliases.cc
libircd_matrix_la_SOURCES += room_bootstrap.cc
libircd_matrix_la_SOURCES += room_create.cc
libircd_matrix_la_SOURCES += room_events.cc
libircd_matrix_la_SOURCES += room_sounding.cc
libircd_matrix_la_SOURCES += room_missing.cc
libircd_matrix_la_SOURCES += room_horizon.cc
libircd_matrix_la_SOURCES += room_head.cc
libircd_matrix_la_SOURCES += room_head_fetch.cc
libircd_matrix_la_SOURCES += room_iterate.cc
libircd_matrix_la_SOURCES += room_state_fetch.cc
libircd_matrix_la_SOURCES += room_join.cc
libircd_matrix_la_SOURCES += room_leave.cc
libircd_matrix_la_SOURCES += room_visible.cc
libircd_matrix_la_SOURCES += room_members.cc
libircd_matrix_la_SOURCES += room_origins.cc
libircd_matrix_la_SOURCES += room_type.cc
libircd_matrix_la_SOURCES += room_message.cc
libircd_matrix_la_SOURCES += room_messages.cc
libircd_matrix_la_SOURCES += room_power.cc
libircd_matrix_la_SOURCES += room_purge.cc
libircd_matrix_la_SOURCES += room_state.cc
libircd_matrix_la_SOURCES += room_state_history.cc
libircd_matrix_la_SOURCES += room_state_space.cc
libircd_matrix_la_SOURCES += room_server_acl.cc
libircd_matrix_la_SOURCES += room_stats.cc
libircd_matrix_la_SOURCES += user.cc
libircd_matrix_la_SOURCES += user_account_data.cc
libircd_matrix_la_SOURCES += user_devices.cc
libircd_matrix_la_SOURCES += user_events.cc
libircd_matrix_la_SOURCES += user_filter.cc
libircd_matrix_la_SOURCES += user_ignores.cc
libircd_matrix_la_SOURCES += user_keys.cc
libircd_matrix_la_SOURCES += user_mitsein.cc
libircd_matrix_la_SOURCES += user_notifications.cc
libircd_matrix_la_SOURCES += user_profile.cc
libircd_matrix_la_SOURCES += user_pushers.cc
libircd_matrix_la_SOURCES += user_pushrules.cc
libircd_matrix_la_SOURCES += user_register.cc
libircd_matrix_la_SOURCES += user_room_account_data.cc
libircd_matrix_la_SOURCES += user_room_tags.cc
libircd_matrix_la_SOURCES += user_rooms.cc
libircd_matrix_la_SOURCES += user_tokens.cc
libircd_matrix_la_SOURCES += acquire.cc
libircd_matrix_la_SOURCES += app.cc
libircd_matrix_la_SOURCES += bridge.cc
libircd_matrix_la_SOURCES += breadcrumbs.cc
libircd_matrix_la_SOURCES += burst.cc
libircd_matrix_la_SOURCES += display_name.cc
libircd_matrix_la_SOURCES += event_append.cc
libircd_matrix_la_SOURCES += event_horizon.cc
libircd_matrix_la_SOURCES += events.cc
libircd_matrix_la_SOURCES += fed.cc
libircd_matrix_la_SOURCES += fed_well_known.cc
libircd_matrix_la_SOURCES += feds.cc
libircd_matrix_la_SOURCES += fetch.cc
libircd_matrix_la_SOURCES += fetch_check.cc
libircd_matrix_la_SOURCES += gossip.cc
libircd_matrix_la_SOURCES += groups.cc
libircd_matrix_la_SOURCES += relates.cc
libircd_matrix_la_SOURCES += request.cc
libircd_matrix_la_SOURCES += keys.cc
libircd_matrix_la_SOURCES += media.cc
libircd_matrix_la_SOURCES += node.cc
libircd_matrix_la_SOURCES += presence.cc
libircd_matrix_la_SOURCES += pretty.cc
libircd_matrix_la_SOURCES += receipt.cc
libircd_matrix_la_SOURCES += rooms.cc
libircd_matrix_la_SOURCES += membership.cc
libircd_matrix_la_SOURCES += rooms_summary.cc
libircd_matrix_la_SOURCES += sync.cc
libircd_matrix_la_SOURCES += trace.cc
libircd_matrix_la_SOURCES += typing.cc
libircd_matrix_la_SOURCES += users.cc
libircd_matrix_la_SOURCES += users_servers.cc
libircd_matrix_la_SOURCES += error.cc
libircd_matrix_la_SOURCES += push.cc
libircd_matrix_la_SOURCES += filter.cc
libircd_matrix_la_SOURCES += txn.cc
libircd_matrix_la_SOURCES += vm.cc
libircd_matrix_la_SOURCES += vm_seq.cc
libircd_matrix_la_SOURCES += vm_eval.cc
libircd_matrix_la_SOURCES += vm_inject.cc
libircd_matrix_la_SOURCES += vm_execute.cc
libircd_matrix_la_SOURCES += vm_fetch.cc
libircd_matrix_la_SOURCES += vm_conforms.cc
libircd_matrix_la_SOURCES += vm_notify.cc
libircd_matrix_la_SOURCES += init_backfill.cc
libircd_matrix_la_SOURCES += homeserver.cc
libircd_matrix_la_SOURCES += homeserver_bootstrap.cc
libircd_matrix_la_SOURCES += resource.cc
libircd_matrix_la_SOURCES += matrix.cc

#
# Unit configurations
#

if CLANG_PCH
SPIRIT_UNIT_CPPFLAGS += -include ircd/spirit.h
#SPIRIT_UNIT_CPPFLAGS += -include-pch $(top_srcdir)/include/ircd/spirit.h.gch
else
SPIRIT_UNIT_CPPFLAGS += -include ircd/spirit.h
endif

id.lo: AM_CPPFLAGS   := ${AM_CPPFLAGS} ${SPIRIT_UNIT_CPPFLAGS}
id.lo: CXXFLAGS      += ${AM_CXXFLAGS} ${SPIRIT_UNIT_CXXFLAGS}
