use @exit[None](errno: I32)
use "cli"
use "collections"
use "ponyzip"
use "debug"
use "regex"

actor Main
  new create(env: Env) =>
    let cs =
      try
        CommandSpec.leaf("jndi-file-scanner", "CLI program to help you find vulnerable artifacts", [
          OptionSpec.bool("all", "All filenames" where short' = 'a', default' = false)
          OptionSpec.string("regex", "Custom Regex" where short' = 'r', default' = "JndiLookup")
          OptionSpec.string("filename", "File to search" where short' = 'f')
        ], [
        ])? .> add_help()?
      else
        @exit(-1)
        return
      end

    let cmd =
      match CommandParser(cs).parse(env.args, env.vars)
      | let c: Command => c
      | let ch: CommandHelp =>
        ch.print_help(env.out)
        @exit(-1)
        return
      | let se: SyntaxError =>
        env.out.print(se.string())
        @exit(-1)
        return
    end

    let filename: String = cmd.option("filename").string()
    var regex: String = cmd.option("regex").string()
    if (cmd.option("all").bool()) then regex = "." end

    try
      let r: Regex = Regex(regex)?

      let analyze: Analyze = Analyze.create_from_file(env, filename, r)
      if ((not analyze.zipptr.valid()) and (analyze.filecount > 0)) then
        env.err.print("Failed to open " + filename + ", " + analyze.zipptr.errorstr)
        @exit(1)
      end
      analyze.report()
      analyze.recurse(2)

    end

class Analyze
  let env: Env
  let filename: String val
  var zipptr: PonyZip
  var filecount: USize = 0
  var r: Regex

  var recursefiles: Array[Zipstat] = []
  var r_of_note: Array[String] = []

  new create_from_file(env': Env, filename': String val, r': Regex) =>
    env = env'
    filename = filename'
    r = r'

    let rdf: ZipFlags = ZipFlags.>set(ZipRDOnly).>set(ZipCheckcons)
    zipptr = PonyZip(filename, rdf)
    if (not zipptr.valid()) then env.out.print(filename + ": " + zipptr.errorstr) ; @exit(-1) end
    try filecount = zipptr.count()? end
    run()

  new create_from_source(env': Env, filename': String val, source: NullablePointer[Zipsource], r': Regex) =>
    env = env'
    filename = filename'
    r = r'

    let rdf: ZipFlags = ZipFlags.>set(ZipRDOnly).>set(ZipCheckcons)
    zipptr = PonyZip.create_from_source(source, rdf)
    try filecount = zipptr.count()? end
    run()

  fun ref report() =>
    for fname in r_of_note.values() do
      env.out.print("FOUND -> " + filename + " -> " + fname)
    end

  fun ref recurse(maxdepth: USize) =>
    for zipstat in recursefiles.values() do
      try
        let source: NullablePointer[Zipsource] = readsource(zipstat)?
        let analyze1: Analyze = Analyze.create_from_source(env, filename + " -> " + zipstat.name(), source, r)
        analyze1.report()
        analyze1.recurse(0)
      else
        env.out.print("I errored on " + zipstat.name())
      end
    end

  fun ref readfile(zipstat: Zipstat): Array[U8] iso^ ? =>
    zipptr.readfile(zipstat)?

  fun ref readsource(zipstat: Zipstat): NullablePointer[Zipsource] ? =>
    let size: USize = zipstat.size()
    let data: Array[U8] iso = zipptr.readfile(zipstat)?
    let ziperror: Ziperror = Ziperror
    ABLibZIP.pzip_source_buffer_create(data.cpointer(), size.u64(), 1, NullablePointer[Ziperror](ziperror))

  fun ref run() =>
    try
      let jar: Regex = Regex("\\.jar$")?
      let ear: Regex = Regex("\\.ear$")?
      let zip: Regex = Regex("\\.zip$")?
      let war: Regex = Regex("\\.war$")?

      for fptr in Range(0, filecount) do
        let zipstat: Zipstat = zipptr.zip_stat_index(fptr)?
        let fname: String = zipstat.name()
        if (r == fname) then r_of_note.push(fname) end
        if (jar == fname.lower()) then recursefiles.push(zipstat) end
        if (ear == fname.lower()) then recursefiles.push(zipstat) end
        if (zip == fname.lower()) then recursefiles.push(zipstat) end
        if (war == fname.lower()) then recursefiles.push(zipstat) end
      end
    end

