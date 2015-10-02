#
# This class manages a syslog-ng server. It can be uses for standard logging or
# complex client/server setups
#
# === Parameters
#
# See README.md for a detailed parameter description
#
# === Variables
#
# No variables required. See params.pp for options.
#
# === Examples
#
# Basic setup:
#
#  import syslog_ng
#
# Some special logging
#
#  syslog_ng::destination::file {'d_file':
#    file => '/var/log/myapp.log'
#  }
#  syslog_ng::filter {'f_mypp':
#    spec => 'program(myapp_name)
#  }
#  syslog_ng::filter {'f_app_server':
#    spec => 'host(appserver.example.org)'
#  }
#  syslog_ng::log {'l_my_app':
#    source      => 's_src',
#    filter      => ['f_myapp', 'f_app_server'],
#    destination => 'd_file'
#  }
#
# === Authors
#
# Sören Berger <soeren.berger@u1337.de>
#
# === Copyright
#
# Copyright 2015 Sören Berger.
#

class syslog_ng (
  $bad_hostname                     = $syslog_ng::params::bad_hostname,
  $chain_hostnames                  = $syslog_ng::params::chain_hostnames,
  $check_hostname                   = $syslog_ng::params::check_hostname,
  $config_dir                       = $syslog_ng::params::config_dir,
  $create_dirs                      = $syslog_ng::params::create_dirs,
  $custom_domain                    = $syslog_ng::params::custom_domain,
  $default_group                    = $syslog_ng::params::default_group,
  $default_owner                    = $syslog_ng::params::default_owner,
  $default_perm                     = $syslog_ng::params::default_perm,
  $dir_group                        = $syslog_ng::params::dir_group,
  $dir_owner                        = $syslog_ng::params::dir_owner,
  $dir_perm                         = $syslog_ng::params::dir_perm,
  $dns_cache                        = $syslog_ng::params::dns_cache,
  $dns_cache_expire                 = $syslog_ng::params::dns_cache_expire,
  $dns_cache_expire_failed          = $syslog_ng::params::dns_cache_expire_failed,
  $dns_cache_hosts                  = $syslog_ng::params::dns_cache_hosts,
  $dns_cache_size                   = $syslog_ng::params::dns_cache_size,
  $file_template                    = $syslog_ng::params::file_template,
  $flush_lines                      = $syslog_ng::params::flush_lines,
  $frac_digits                      = $syslog_ng::params::frac_digits,
  $group                            = $syslog_ng::params::group,
  $keep_hostname                    = $syslog_ng::params::keep_hostname,
  $keep_timestamp                   = $syslog_ng::params::keep_timestamp,
  $local_source                     = $syslog_ng::params::local_source,
  $log_fifo_size                    = $syslog_ng::params::log_fifo_size,
  $log_fifo_size_destination        = $syslog_ng::params::log_fifo_size_destination,
  $log_msg_size                     = $syslog_ng::params::log_msg_size,
  $logstore_journal_shmem_threshold = $syslog_ng::params::logstore_journal_shmem_threshold,
  $mark_freq                        = $syslog_ng::params::mark_freq,
  $mark_mode                        = $syslog_ng::params::mark_mode,
  $normalize_hostnames              = $syslog_ng::params::normalize_hostnames,
  $on_error                         = $syslog_ng::params::on_error,
  $owner                            = $syslog_ng::params::owner,
  $perm                             = $syslog_ng::params::perm,
  $proto_template                   = $syslog_ng::params::proto_template,
  $recv_time_zone                   = $syslog_ng::params::recv_time_zone,
  $reminder_file                    = $syslog_ng::params::reminder_file,
  $send_time_zone                   = $syslog_ng::params::send_time_zone,
  $stats_freq                       = $syslog_ng::params::stats_freq,
  $stats_level                      = $syslog_ng::params::stats_level,
  $system_log_dir                   = $syslog_ng::params::system_log_dir,
  $threaded                         = $syslog_ng::params::threaded,
  $time_reap                        = $syslog_ng::params::time_reap,
  $time_reopen                      = $syslog_ng::params::time_reopen,
  $time_zone                        = $syslog_ng::params::time_zone,
  $timestamp_freq                   = $syslog_ng::params::timestamp_freq,
  $timestamp_policy                 = $syslog_ng::params::timestamp_policy,
  $timestamp_url                    = $syslog_ng::params::timestamp_url,
  $ts_format                        = $syslog_ng::params::ts_format,
  $use_dns                          = $syslog_ng::params::use_dns,
  $use_fqdn                         = $syslog_ng::params::use_fqdn,
  $use_uniqid                       = $syslog_ng::params::use_uniqid,
) inherits ::syslog_ng::params {
  $fragments = [
    $syslog_ng::params::config_file_sources,
    $syslog_ng::params::config_file_destination_files,
    $syslog_ng::params::config_file_destination_fallback,
    $syslog_ng::params::config_file_destination_remote,
    $syslog_ng::params::config_file_filter,
    $syslog_ng::params::config_file_parser,
    $syslog_ng::params::config_file_logging,
    $syslog_ng::params::config_file_fallback,
  ]
  concat {$fragments:
    force  => true,
    warn   => '# This file is generated by puppet',
    notify => Service[syslog_ng],
    owner  => 'root',
    group  => 'root',
    mode   => '0644'
  }
  include syslog_ng::install
  include syslog_ng::service
}


#
# Parser
#

define syslog_ng::parser (
  $spec   = undef,
  $target = $::syslog_ng::config_file_parser,
  ) {
  $entry_type = 'parser'
  concat::fragment{ $name:
    target  => $target,
    content => template('syslog_ng/entry.erb')
  }
}

#
# rewrite
#

define syslog_ng::rewrite (
  $spec   = undef,
  $target = $::syslog_ng::config_file_rewrite,
  ) {
  $entry_type = 'rewrite'
  concat::fragment{ $name:
    target  => $target,
    content => template('syslog_ng/entry.erb')
  }
}

#
# Filters
#

define syslog_ng::filter (
  $spec = undef,
  ) {
  $entry_type = 'filter'
  concat::fragment{ "${name}_fallback":
    target  => $::syslog_ng::config_file_filter,
    content => template('syslog_ng/entry.erb')
  }
}

#
# Logging
#

define syslog_ng::log (
  $source          = $::syslog_ng::local_source,
  $filter          = undef,
  $filter_spec     = undef,
  $parser          = undef,
  $rewrite         = undef,
  $destination     = undef,
  $file            = undef,
  $fallback        = undef,
  $owner           = undef,
  $group           = undef,
  $dir_owner       = undef,
  $dir_group       = undef,
  $perm            = undef,
  ) {
  validate_string($source)
  if $fallback {
    $target = $::syslog_ng::config_file_fallback
  }
  else {
    $target = $::syslog_ng::config_file_logging
  }
  if $file {
    syslog_ng::destination::file {"d_${name}":
      file      => $file,
      owner     => $owner,
      group     => $group,
      dir_owner => $dir_owner,
      dir_group => $dir_group,
      perm      => $perm
    }
  }
  if $filter_spec {
    syslog_ng::filter {"f_${name}":
      spec => $filter_spec
    }
  }
  concat::fragment{ "${name}_log":
    target  => $target,
    content => template('syslog_ng/log.erb'),
  }
}

