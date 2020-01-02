{-# LANGUAGE OverloadedStrings, DataKinds #-}

module Proof where

import Control.Exception

import Data.Foldable (forM_)
import Data.ByteString (ByteString)

import Data.Parameterized.Classes

import SAWScript.Prover.SolverStats
import SAWScript.Prover.SBV
import SAWScript.X86
import SAWScript.X86Spec
import Data.Macaw.Types (Type(..))
import Data.Macaw.X86.X86Reg
import Verifier.SAW.CryptolEnv (CryptolEnv)

globals :: [(ByteString, Integer, Unit)]
globals =
  [ ("p434", constant_NWORDS_FIELD, type_digit_t)
  , ("p434p1", constant_NWORDS_FIELD, type_digit_t)
  , ("p434x2", constant_NWORDS_FIELD, type_digit_t)
  ]

type_digit_t :: Unit
type_digit_t = QWords

constant_NWORDS_FIELD :: Integer
constant_NWORDS_FIELD = 7

fpadd434_asm_spec :: CryptolEnv -> IO Specification
fpadd434_asm_spec _ =
  pure Specification
    { specAllocs =
      [ InReg RSP := Area { areaName = "stack"
                          , areaMode = RW
                          , areaSize = (1 + 6, QWords)
                          , areaHasPointers = False
                          , areaPtr = 6 *. QWords
                          }
      , InReg RDI := area "reg_p1" RO constant_NWORDS_FIELD type_digit_t
      , InReg RSI := area "reg_p2" RO constant_NWORDS_FIELD type_digit_t
      , InReg RDX := area "reg_p3" WO constant_NWORDS_FIELD type_digit_t
      ]
    , specPres = []
    , specPosts =
      [ ( "IP not restored"
        , PreLoc (inMem (InReg RSP) 0 QWords) === Loc (InReg X86_IP)
        )
      , ( "stack not restored"
        , PreAddPtr (InReg RSP) 1 QWords === Loc (InReg RSP)
        )
      , ( "return value initialized"
        , Initialized (PreLoc (InReg RDX)) constant_NWORDS_FIELD type_digit_t
        )
      ]
    , specGlobsRO = []
    , specCalls = []
    }

fpsub434_asm_spec :: CryptolEnv -> IO Specification
fpsub434_asm_spec _ =
  pure Specification
    { specAllocs =
      [ InReg RSP := Area { areaName = "stack"
                          , areaMode = RW
                          , areaSize = (1 + 3, QWords)
                          , areaHasPointers = False
                          , areaPtr = 3 *. QWords
                          }
      , InReg RDI := area "reg_p1" RO constant_NWORDS_FIELD type_digit_t
      , InReg RSI := area "reg_p2" RO constant_NWORDS_FIELD type_digit_t
      , InReg RDX := area "reg_p3" WO constant_NWORDS_FIELD type_digit_t
      ]
    , specPres = []
    , specPosts =
      [ ( "IP not restored"
        , PreLoc (inMem (InReg RSP) 0 QWords) === Loc (InReg X86_IP)
        )
      , ( "stack not restored"
        , PreAddPtr (InReg RSP) 1 QWords === Loc (InReg RSP)
        )
      , ( "return value initialized"
        , Initialized (PreLoc (InReg RDX)) constant_NWORDS_FIELD type_digit_t
        )
      ]
    , specGlobsRO = []
    , specCalls = []
    }

mul434_asm_spec :: CryptolEnv -> IO Specification
mul434_asm_spec _ =
  pure Specification
    { specAllocs =
      [ InReg RSP := Area { areaName = "stack"
                          , areaMode = RW
                          , areaSize = (1 + 18, QWords)
                          , areaHasPointers = False
                          , areaPtr = 18 *. QWords
                          }
      , InReg RDI := area "reg_p1" RO constant_NWORDS_FIELD type_digit_t
      , InReg RSI := area "reg_p2" RO constant_NWORDS_FIELD type_digit_t
      , InReg RDX := area "reg_p3" WO (2 * constant_NWORDS_FIELD) type_digit_t
      ]
    , specPres = []
    , specPosts =
      [ ( "IP not restored"
        , PreLoc (inMem (InReg RSP) 0 QWords) === Loc (InReg X86_IP)
        )
      , ( "stack not restored"
        , PreAddPtr (InReg RSP) 1 QWords === Loc (InReg RSP)
        )
      , ( "return value initialized"
        , Initialized (PreLoc (InReg RDX)) constant_NWORDS_FIELD type_digit_t
        )
      ]
    , specGlobsRO = []
    , specCalls = []
    }

rdc434_asm_spec :: CryptolEnv -> IO Specification
rdc434_asm_spec _ =
  pure Specification
    { specAllocs =
      [ InReg RSP := Area { areaName = "stack"
                          , areaMode = RW
                          , areaSize = (1 + 2, QWords)
                          , areaHasPointers = False
                          , areaPtr = 2 *. QWords
                          }
      , InReg RDI := area "reg_p1" RW (2 * constant_NWORDS_FIELD) type_digit_t
      , InReg RSI := area "reg_p2" WO constant_NWORDS_FIELD type_digit_t
      ]
    , specPres = []
    , specPosts =
      [ ( "IP not restored"
        , PreLoc (inMem (InReg RSP) 0 QWords) === Loc (InReg X86_IP)
        )
      , ( "stack not restored"
        , PreAddPtr (InReg RSP) 1 QWords === Loc (InReg RSP)
        )
      , ( "return value initialized"
        , Initialized (PreLoc (InReg RSI)) constant_NWORDS_FIELD type_digit_t
        )
      ]
    , specGlobsRO = []
    , specCalls = []
    }

mp_add434_asm_spec :: CryptolEnv -> IO Specification
mp_add434_asm_spec _ =
  pure Specification
    { specAllocs =
      [ InReg RSP := Area { areaName = "stack"
                          , areaMode = RW
                          , areaSize = (1 + 0, QWords)
                          , areaHasPointers = False
                          , areaPtr = 0 *. QWords
                          }
      , InReg RDI := area "reg_p1" RO constant_NWORDS_FIELD type_digit_t
      , InReg RSI := area "reg_p2" RO constant_NWORDS_FIELD type_digit_t
      , InReg RDX := area "reg_p3" WO constant_NWORDS_FIELD type_digit_t
      ]
    , specPres = []
    , specPosts =
      [ ( "IP not restored"
        , PreLoc (inMem (InReg RSP) 0 QWords) === Loc (InReg X86_IP)
        )
      , ( "stack not restored"
        , PreAddPtr (InReg RSP) 1 QWords === Loc (InReg RSP)
        )
      , ( "return value initialized"
        , Initialized (PreLoc (InReg RDX)) constant_NWORDS_FIELD type_digit_t 
        )
      ]
    , specGlobsRO = []
    , specCalls = []
    }

mp_sub434x2_asm_spec :: CryptolEnv -> IO Specification
mp_sub434x2_asm_spec _ =
  pure Specification
    { specAllocs =
      [ InReg RSP := Area { areaName = "stack"
                          , areaMode = RW
                          , areaSize = (1 + 0, QWords)
                          , areaHasPointers = False
                          , areaPtr = 0 *. QWords
                          }
      , InReg RDI := area "reg_p1" RO (2 * constant_NWORDS_FIELD) type_digit_t
      , InReg RSI := area "reg_p2" RO (2 * constant_NWORDS_FIELD) type_digit_t
      , InReg RDX := area "reg_p3" WO (2 * constant_NWORDS_FIELD) type_digit_t
      ]
    , specPres = []
    , specPosts =
      [ ( "IP not restored"
        , PreLoc (inMem (InReg RSP) 0 QWords) === Loc (InReg X86_IP)
        )
      , ( "stack not restored"
        , PreAddPtr (InReg RSP) 1 QWords === Loc (InReg RSP)
        )
      , ( "return value initialized"
        , Initialized (PreLoc (InReg RDX)) (2 * constant_NWORDS_FIELD) type_digit_t 
        )
      ]
    , specGlobsRO = []
    , specCalls = []
    }

mp_dblsub434x2_asm_spec :: CryptolEnv -> IO Specification
mp_dblsub434x2_asm_spec _ =
  pure Specification
    { specAllocs =
      [ InReg RSP := Area { areaName = "stack"
                          , areaMode = RW
                          , areaSize = (1 + 2, QWords)
                          , areaHasPointers = False
                          , areaPtr = 2 *. QWords
                          }
      , InReg RDI := area "reg_p1" RO (2 * constant_NWORDS_FIELD) type_digit_t
      , InReg RSI := area "reg_p2" RO (2 * constant_NWORDS_FIELD) type_digit_t
      , InReg RDX := area "reg_p3" RW (2 * constant_NWORDS_FIELD) type_digit_t
      ]
    , specPres = []
    , specPosts =
      [ ( "IP not restored"
        , PreLoc (inMem (InReg RSP) 0 QWords) === Loc (InReg X86_IP)
        )
      , ( "stack not restored"
        , PreAddPtr (InReg RSP) 1 QWords === Loc (InReg RSP)
        )
      , ( "return value initialized"
        , Initialized (PreLoc (InReg RDX)) (2 * constant_NWORDS_FIELD) type_digit_t 
        )
      ]
    , specGlobsRO = []
    , specCalls = []
    }

prove :: ByteString -> (CryptolEnv -> IO Specification) -> IO ()
prove name spec = do
  (ctx, _, gs) <- proof linuxInfo "bin/test" Nothing globals
    Fun { funName = name
        , funSpec = NewStyle spec . const $ pure ()
        }
  print gs
  forM_ gs $ \g ->
    do term <- gGoal ctx g
       (mb, stats) <- proveUnintSBV z3 [] Nothing ctx term
       putStrLn $ ppStats stats
       case mb of
         Nothing -> putStrLn "success!"
         Just ex -> putStrLn "failure, counterexample:" *> print ex
    `catch` \(X86Error e) -> putStrLn "proof failed! error:" *> putStrLn e

result :: IO ()
result = do
  prove "fpadd434_asm" fpadd434_asm_spec
  prove "fpsub434_asm" fpsub434_asm_spec
  prove "mul434_asm" mul434_asm_spec
  prove "rdc434_asm" rdc434_asm_spec
  prove "mp_add434_asm" mp_add434_asm_spec
  -- prove "mp_sub434x2_asm" mp_sub434x2_asm_spec
  prove "mp_dblsub434x2_asm" mp_dblsub434x2_asm_spec
