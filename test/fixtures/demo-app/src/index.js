// Demo app for Pathwise/Todoku. One of each outcome:
//  - lodash is imported and used                      -> reachable (direct dependency)
//  - debug is used; its library code requires ms      -> reachable via a TRANSITIVE dependency
//  - mkdirp is used, but only its bin/cmd.js (never loaded here) requires minimist@0.0.8
//                                                     -> present but unreachable (transitive)
//  - the top-level minimist@1.2.0 is declared, never imported -> present but unreachable (direct)
const _ = require("lodash");
const debug = require("debug")("demo");
const mkdirp = require("mkdirp");

mkdirp.sync("out");
debug("starting");
console.log(_.template("hello <%= name %>")({ name: "world" }));
