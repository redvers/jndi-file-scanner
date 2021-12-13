use @exit[None](errno: I32)
use "collections"
use "ponyzip"
use "debug"
use "regex"

actor Main
  new create(env: Env) =>
    try
      let filename: String val = env.args(1)?
      env.err.print("Attempting to read: " + filename)

      let analyze: Analyze = Analyze.create_from_file(env, filename)
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

  var recursefiles: Array[Zipstat] = []
  var jndi_of_note: Array[String] = []
  var log4jof_note: Array[String] = []

  new create_from_file(env': Env, filename': String val) =>
    env = env'
    filename = filename'

    let rdf: ZipFlags = ZipFlags.>set(ZipRDOnly).>set(ZipCheckcons)
    zipptr = PonyZip(filename, rdf)
    try filecount = zipptr.count()? end
    run()

  new create_from_source(env': Env, filename': String val, source: NullablePointer[Zipsource]) =>
    env = env'
    filename = filename'

    let rdf: ZipFlags = ZipFlags.>set(ZipRDOnly).>set(ZipCheckcons)
    zipptr = PonyZip.create_from_source(source, rdf)
    try filecount = zipptr.count()? end
    run()

  fun ref report() =>
    for fname in log4jof_note.values() do
      env.out.print("LOG4J -> " + filename + " -> " + fname)
    end
    for fname in jndi_of_note.values() do
      env.out.print("JNDI -> " + filename + " -> " + fname)
    end
//    for zipstat in recursefiles.values() do
//      env.err.print("RECURSE -> " + filename + ": " + zipstat.name())
//    end

  fun ref recurse(maxdepth: USize) =>
    for zipstat in recursefiles.values() do
      try
        let source: NullablePointer[Zipsource] = readsource(zipstat)?
        let analyze1: Analyze = Analyze.create_from_source(env, filename + " -> " + zipstat.name(), source)
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

      let log4j: Regex = Regex("log4j")?
      let jndilookup: Regex = Regex("JndiLookup")?

      for fptr in Range(0, filecount) do
        let zipstat: Zipstat = zipptr.zip_stat_index(fptr)?
        let fname: String = zipstat.name()
        if (log4j == fname.lower()) then log4jof_note.push(fname) end
        if (jndilookup == fname.lower()) then jndi_of_note.push(fname) end
        if (jar == fname.lower()) then recursefiles.push(zipstat) end
        if (ear == fname.lower()) then recursefiles.push(zipstat) end
        if (zip == fname.lower()) then recursefiles.push(zipstat) end
        if (war == fname.lower()) then recursefiles.push(zipstat) end
      end
    end

