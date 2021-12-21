use @exit[None](errno: I32)
use "cli"
use "collections"
use "ponyzip"
use "debug"
use "regex"
use "format"
use "crypto"

actor Main
  var crc: Bool = false
  var sha256: Bool = false
  new create(env: Env) =>
    let cs =
      try
        CommandSpec.leaf("jndi-file-scanner", "CLI program to help you find vulnerable artifacts", [
          OptionSpec.bool("all", "All filenames" where short' = 'a', default' = false)
          OptionSpec.bool("insensitive", "Case Insensitive" where short' = 'i', default' = false)
          OptionSpec.bool("crc", "output zipfile crc" where short' = 'c', default' = false)
          OptionSpec.bool("sha256", "output calculated sha256" where short' = 's', default' = false)
          OptionSpec.string("regex", "Custom Regex" where short' = 'r', default' = "(?i)JndiLookup.class")
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
    if (cmd.option("insensitive").bool()) then regex = "(?i)" + regex end
    if (cmd.option("crc").bool()) then crc = true end
    if (cmd.option("sha256").bool()) then sha256 = true end

    try
      let r: Regex = Regex(regex)?

      let analyze: Analyze = Analyze.create_from_file(env, filename, r, crc, sha256)
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
  let crc: Bool
  let sha256: Bool

  var recursefiles: Array[Zipstat] = []
  var r_of_note: Array[Zipstat] = []

  new create_from_file(env': Env, filename': String val, r': Regex, crc': Bool, sha256': Bool) =>
    env = env'
    filename = filename'
    r = r'
    crc = crc'
    sha256 = sha256'

    let rdf: ZipFlags = ZipFlags.>set(ZipRDOnly).>set(ZipCheckcons)
    zipptr = PonyZip(filename, rdf)
    if (not zipptr.valid()) then env.out.print(filename + ": " + zipptr.errorstr) ; @exit(-1) end
    try filecount = zipptr.count()? end
    run()

  new create_from_source(env': Env, filename': String val, source: NullablePointer[Zipsource], r': Regex, crc': Bool, sha256': Bool) =>
    env = env'
    filename = filename'
    r = r'
    crc = crc'
    sha256 = sha256'

    let rdf: ZipFlags = ZipFlags.>set(ZipRDOnly).>set(ZipCheckcons)
    zipptr = PonyZip.create_from_source(source, rdf)
    try filecount = zipptr.count()? end
    run()

  fun ref report() =>
    for zipstat in r_of_note.values() do
      if (crc) then
        let str: String = Format.int[U32](zipstat.pcrc where width = 8, align = AlignRight, fmt = FormatHexBare, fill = '0')
        env.out.write("CRC:" + str + ": ")
      end

      if (sha256) then
        try
          let filecontent: Array[U8] iso = zipptr.readfile(zipstat)?
          let str: Array[U8] val = SHA256(consume filecontent)
          env.out.write("SHA256:")
          for chr in str.values() do
            env.out.write(Format.int[U8](chr where prec=2, fmt = FormatHexSmallBare))
          end
          env.out.write(": ")
        end
      end

      env.out.print("FOUND -> " + filename + " -> " + zipstat.name())
    end

  fun ref recurse(maxdepth: USize) =>
    for zipstat in recursefiles.values() do
      try
        let source: NullablePointer[Zipsource] = readsource(zipstat)?
        let analyze1: Analyze = Analyze.create_from_source(env, filename + " -> " + zipstat.name(), source, r, crc, sha256)
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
        if (r == fname) then r_of_note.push(zipstat) end
        if (jar == fname.lower()) then recursefiles.push(zipstat) end
        if (ear == fname.lower()) then recursefiles.push(zipstat) end
        if (zip == fname.lower()) then recursefiles.push(zipstat) end
        if (war == fname.lower()) then recursefiles.push(zipstat) end
      end
    end

