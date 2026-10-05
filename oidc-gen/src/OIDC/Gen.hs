{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | Generators for the types "OIDC" asks a caller to build.
--
-- These are here rather than in the library so that nothing that depends on
-- the library has to build QuickCheck to use it.
module OIDC.Gen () where

import Data.GenValidity
import Data.GenValidity.Text ()
import Data.GenValidity.Time ()
import OIDC
import Test.QuickCheck

instance GenValid Algorithm

instance GenValid Issuer

instance GenValid TokenAudience

instance GenValid Discovery

instance GenValid Verification where
  shrinkValid = shrinkValidStructurally
  genValid = do
    verificationIssuer <- genValid
    verificationAudiences <- genValid
    verificationAlgorithms <- genValid
    -- A maximum lifetime of zero would refuse every token there is, and a
    -- negative skew would refuse every clock, so neither is a configuration a
    -- caller can hold.
    verificationMaxTokenLifetime <- genValid `suchThat` all (> 0)
    verificationClockSkew <- genValid `suchThat` (>= 0)
    pure Verification {..}
