open Regular.Std
open Graphlib.Std
open Bap.Std
open Format
include Self()

let pp_fn ppf (name,_,g) =
  Graphlib.to_dot (module Graphs.Cfg)
    ~formatter:ppf
    ~graph_attrs:(fun _ -> [`Label name])
    ~string_of_node:(fun n ->
        sprintf "%S" @@ Addr.string_of_value (Block.addr n))
    g

let pp_cfg ppf proj =
  Project.symbols proj |>
  Symtab.to_sequence |>
  Seq.iter ~f:(fprintf ppf "%a@\n" pp_fn)

let () = Config.when_ready (fun _ ->
    Project.add_writer ~ver:"1.0.0"
      ~desc:"print a simple CFG"
      "rcfg"
      (Data.Write.create ~pp:pp_cfg ()))
