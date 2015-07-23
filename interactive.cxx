// systemtap interactive mode
// Copyright (C) 2015 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "config.h"
#include "interactive.h"
#include "session.h"
#include "util.h"

#include "stap-probe.h"

#include <cstdlib>

using namespace std;

extern "C" {
#include <unistd.h>
#include <stdlib.h>
#include <readline/readline.h>
#include <readline/history.h>
}

// FIXME: these declarations don't really belong here.
extern int
passes_0_4 (systemtap_session &s);
extern int
pass_5 (systemtap_session &s, vector<remote*> targets);

// Class that describes an interactive command or an option for the
// set/show commands.
class cmdopt
{
protected:
  string _help_text;
public:
  string name;
  string usage;
  virtual string help_text(size_t indent) const { return _help_text; }
  virtual bool handler(systemtap_session &s, vector<string> &tokens) = 0;
};

typedef vector<cmdopt*> cmdopt_vector;
typedef vector<cmdopt*>::const_iterator cmdopt_vector_const_iterator;
typedef vector<cmdopt*>::iterator cmdopt_vector_iterator;
static cmdopt_vector commands;
static cmdopt_vector options;
static void interactive_usage();

//
// Supported commands.
// 

class help_cmd: public cmdopt
{
public:
  help_cmd()
  {
    name = usage = "!help";
    _help_text = "Print this command list";
  }
  virtual bool handler(systemtap_session &s, vector<string> &tokens)
  {
    interactive_usage();
    return false;
  }
};

class list_cmd : public cmdopt
{
public:
  list_cmd()
  {
    name = usage = "!list";
    _help_text = "Display the current script";
  }
  bool handler(systemtap_session &s, vector<string> &tokens)
  {
    // FIXME: Hmm, we might want to use 'printscript' here...
    if (s.have_script)
      cout << s.cmdline_script << endl;
    else
      cout << "(No script input.)" << endl;
    return false;
  }
};

class set_cmd: public cmdopt
{
public:
  set_cmd()
  {
    name = "!set";
    usage = "!set OPTION VALUE";
    _help_text = "Set option value. Supported options are:";
  }
  string help_text(size_t indent) const
  {
    ostringstream buffer;
    size_t width = 1;

    // Find biggest option "name" field.
    for (cmdopt_vector_const_iterator it = options.begin();
	 it != options.end(); ++it)
      {
	if ((*it)->name.size() > width)
	  width = (*it)->name.size();
      }

    // Add each option to the output.
    buffer << _help_text;
    for (cmdopt_vector_iterator it = options.begin();
	 it != options.end(); ++it)
      {
	buffer << endl << setw(indent + 2) << " ";
	buffer << setw(width) << left << (*it)->name << " -- "
	       << (*it)->help_text(0);
      }
    return buffer.str();
  }
  bool handler(systemtap_session &s, vector<string> &tokens)
  {
    bool option_found = false;
    if (tokens.size() != 3)
      {
	cout << endl << "Invalid command" << endl;
	interactive_usage();
	return false;
      }

    // Search the option list for the option to display.
    for (cmdopt_vector_iterator it = options.begin();
	 it != options.end(); ++it)
      {
	if (tokens[1] == (*it)->name)
	{
	  option_found = true;
	  (*it)->handler(s, tokens);
	  break;
	}
      }
    if (!option_found)
      {
	cout << "Invalid option name" << endl;
	interactive_usage();
      }
    return false;
  }
};

class show_cmd: public cmdopt
{
public:
  show_cmd()
  {
    name = "!show";
    usage = "!show OPTION";
    _help_text = "Show option value";
  }
  bool handler(systemtap_session &s, vector<string> &tokens)
  {
    bool option_found = false;
    if (tokens.size() != 2)
      {
	cout << endl << "Invalid command" << endl;
	interactive_usage();
	return false;
      }

    // Search the option list for the option to display.
    for (cmdopt_vector_iterator it = options.begin();
	 it != options.end(); ++it)
      {
	if (tokens[1] == (*it)->name)
	  {
	    option_found = true;
	    (*it)->handler(s, tokens);
	    break;
	  }
      }
    if (!option_found)
      {
	cout << "Invalid option name" << endl;
	interactive_usage();
      }
    return false;
  }
};

class quit_cmd : public cmdopt
{
public:
  quit_cmd()
  {
    name = usage = "!quit";
    _help_text = "Quit systemtap";
  }
  bool handler(systemtap_session &s, vector<string> &tokens)
  {
    return true;
  }
};

//
// Supported options for the "!set" and "!show" commands.
// 

class keep_tmpdir_opt: public cmdopt
{
public:
  keep_tmpdir_opt()
  {
    name = "keep_tmpdir";
    _help_text = "Keep temporary directory";
  }
  bool handler(systemtap_session &s, vector<string> &tokens)
  {
    bool set = (tokens[0] == "!set");
    if (set)
      s.keep_tmpdir = (tokens[2] != "0");
    else
      cout << name << ": " << s.keep_tmpdir << endl;
    return false;
  }
};

class last_pass_opt: public cmdopt
{
public:
  last_pass_opt()
  {
      name = "last_pass";
      _help_text = "Stop after pass NUM 1-5";
  }
  bool handler(systemtap_session &s, vector<string> &tokens)
  {
    bool set = (tokens[0] == "!set");
    if (set)
      {
	char *end;
	long val;

	errno = 0;
	val = strtol (tokens[2].c_str(), &end, 10);
	if (errno != 0 || *end != '\0' || val < 1 || val > 5)
	  cout << "Invalid option value (should be 1-5)" << endl;
	else
	  s.last_pass = val;
      }
    else
      cout << name << ": " << s.last_pass << endl;
    return false;
  }
};

class verbose_opt: public cmdopt
{
public:
  verbose_opt()
  {
    name = "verbose";
    _help_text = "Add verbosity to all passes";
  }
  bool handler(systemtap_session &s, vector<string> &tokens)
  {
    bool set = (tokens[0] == "!set");
    if (set)
      {
	char *end;
	long val;

	errno = 0;
	val = strtol (tokens[2].c_str(), &end, 10);
	if (errno != 0 || *end != '\0' || val < 0)
	  cout << "Invalid option value (should be greater than 0)" << endl;
	else
	  {
	    s.verbose = val;
	    for (unsigned i=0; i<5; i++)
	      s.perpass_verbose[i] = val;
	  }
      }
    else
      cout << name << ": " << s.verbose << endl;
    return false;
  }
};

static void
interactive_usage ()
{
  cout << "List of commands:" << endl << endl;

  // Find biggest "usage" field.
  size_t width = 1;
  for (cmdopt_vector_const_iterator it = commands.begin();
       it != commands.end(); ++it)
    {
      if ((*it)->usage.size() > width)
	  width = (*it)->usage.size();
    }
  // Print usage field and help text for each command.
  for (cmdopt_vector_const_iterator it = commands.begin();
       it != commands.end(); ++it)
    {
      cout << setw(width) << left << (*it)->usage << " -- "
	   << (*it)->help_text(width + 4) << endl;
    }
}

//
// Interactive mode, passes 0 through 5 and back again.
//

int
interactive_mode (systemtap_session &s, vector<remote*> targets)
{
  int rc;
  string delimiters = " \t";
  bool input_handled;

  // Set up command list.
  commands.push_back(new help_cmd);
  commands.push_back(new list_cmd);
  commands.push_back(new set_cmd);
  commands.push_back(new show_cmd);
  commands.push_back(new quit_cmd);

  // Set up !set/!show option list.
  options.push_back(new keep_tmpdir_opt);
  options.push_back(new last_pass_opt);
  options.push_back(new verbose_opt);

  while (1)
    {
      char *line_tmp = readline("stap> ");
      if (line_tmp && *line_tmp)
	add_history(line_tmp);
      else
	continue;

      string line = string(line_tmp);
      free(line_tmp);

      vector<string> tokens;
      tokenize(line, tokens, delimiters);

      input_handled = false;
      if (tokens.size())
        {
	  bool quit = false;
	  // Search list for command to execute.
	  for (cmdopt_vector_iterator it = commands.begin();
	       it != commands.end(); ++it)
	    {
	      if (tokens[0] == (*it)->name)
	        {
		  input_handled = true;
		  quit = (*it)->handler(s, tokens);
		  break;
		}
	    }
	    
	  if (input_handled && quit)
	    break;
	}

      // If it isn't a command, we assume it is a script to run.
      //
      // FIXME: Later this could be a line from a script that we have
      // to keep track of.
      if (!input_handled)
        {
	  // Try creating a new systemtap session object so that we
	  // don't get leftovers from the last script we compiled.
	  s.clear_script_data();
	  systemtap_session* ss = s.clone(s.architecture, s.kernel_release);

	  ss->cmdline_script = line;
	  ss->have_script = true;
	  rc = passes_0_4(*ss);

	  // Run pass 5, if passes 0-4 worked.
	  if (rc == 0 && ss->last_pass >= 5 && !pending_interrupts)
	    rc = pass_5 (*ss, targets);
	  ss->reset_tmp_dir();
	}
    }
  return 0;
}
