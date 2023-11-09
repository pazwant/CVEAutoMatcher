#!/usr/bin/env ruby

require 'msfenv'
require 'msf/base'

module Msf
  class Plugin::CVEAutoMatcher < Msf::Plugin
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def name
        'Strike'
      end

      def commands
        {
          'match_cves' => 'Automatically match vulnerabilities in the database with corresponding Metasploit modules'
        }
      end

      def cmd_match_cves
        unless framework.db.active
          print_error("The database is not connected. Please connect the database before attempting a match.")
          return
        end

        print_status("Matching CVEs from the database with Metasploit modules and retrieving vulnerable IPs...")
        framework.datastore['ConsoleLogging'] = true
        print_status("ConsoleLogging has been set to true.")
        matched_data = {}

        current_workspace = framework.db.workspace

        # Retrieve all vulnerabilities from the database for the current workspace
        vulns = framework.db.vulns(workspace: current_workspace)

        vulns.each do |vuln|
          vuln.refs.each do |ref|
            if ref.respond_to?(:name) && ref.name.start_with?('CVE-')
              cve_id = ref.name

              # Initialize the data structure for this CVE
              matched_data[cve_id] ||= { modules: [], hosts: [] }

              # Find modules that match the CVE
              search_params = Msf::Modules::Metadata::Search.parse_search_string(cve_id)
              module_search_results = Msf::Modules::Metadata::Cache.instance.find(search_params)

              module_search_results.each do |module_metadata|
                 matched_data[cve_id][:modules] << module_metadata.fullname unless matched_data[cve_id][:modules].include?(module_metadata.fullname)
              end

              # Get the host information from the vulnerability
              host = vuln.host
              matched_data[cve_id][:hosts] << host.address unless matched_data[cve_id][:hosts].include?(host.address)
            end
          end
        end

        if matched_data.empty?
          print_status("No matches found between CVEs in the database and Metasploit modules.")
        else
          matched_data.each do |cve_id, data|
            if data[:modules].any? && data[:hosts].any?
              print_status("CVE: #{cve_id}")
              host_addresses = data[:hosts].join(' ')
              tbl = generate_module_table('Matching Modules')
              count = 0
              data[:modules].each do |module_fullname|
                
                # Assuming we can get a module object by its fullname
                m = framework.modules.create(module_fullname)

                tbl << [
                  count += 1,
                  m.fullname,
                  m.disclosure_date.nil? ? '' : m.disclosure_date.strftime("%Y-%m-%d"),
                  m.rank.to_s,
                  m.respond_to?(:check) ? 'Yes' : 'No',
                  m.name,
                  host_addresses
                ]
              #data[:hosts].each { |ip_address| print_good("\t#{ip_address}") }
              end
              print_line(tbl.to_s)
              
              # Assuming you want to provide the user with commands for the last module matched
              last_module = data[:modules].last
              #print_line("Use command: use #{last_module}")
              end
          end
        end
      end
            # Taken from orijinal search implementation
      def generate_module_table(type, search_terms = [], row_filter = nil)
        Msf::Ui::Console::Table.new(
          Msf::Ui::Console::Table::Style::Default,
          'Header'     => type,
          'Prefix'     => "\n",
          'Postfix'    => "\n",
          'SearchTerm' => row_filter,
          'Columns' => [
            '#',
            'Name',
            'Disclosure Date',
            'Rank',
            'Check',
            'Description',
            'IP Addresses'
          ]
        )
      end
    end

    def initialize(framework, opts)
      super
      add_console_dispatcher(ConsoleCommandDispatcher)
    end

    def cleanup
      remove_console_dispatcher('cveautomatcher')
    end

    def name
      "cveautomatcher"
    end

    def desc
      "A plugin to automatically match CVEs from the database(could be imported from Nessus,NeXpose,etc) with Metasploit modules."
    end
  end
end
