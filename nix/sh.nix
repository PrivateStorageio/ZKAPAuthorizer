{ lib }:
rec {
  # render a list of environment variable values as a single string in shell
  # syntax for setting environment variables to values.
  #
  # [{string, string}] -> string
  envToShell = env: builtins.concatStringsSep " " (lib.attrsets.mapAttrsToList (k: v: "${k}=${v}") env);

  # render a list of argument strings to a single string in shell syntax for
  # passing the strings as arguments to a program.
  argvToShell = builtins.concatStringsSep " ";

  # render a Python argument list, a trial environment, and a trial argument
  # list as a single string in shell-syntax for running trial with that
  # environment and those arguments.
  #
  # [{string: string}] -> [string] -> [string] -> string
  trial = pythonEnv: envVars: pythonArgs: trialArgs: ''
    ${envToShell envVars} ${pythonEnv}/bin/python -m ${argvToShell pythonArgs} twisted.trial ${argvToShell trialArgs}
  '';
}
