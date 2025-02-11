// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gittuf

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/gittuf/gittuf/internal/common/set"
	"github.com/gittuf/gittuf/internal/dev"
	"github.com/gittuf/gittuf/internal/gitinterface"
	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/signerverifier/gpg"
	artifacts "github.com/gittuf/gittuf/internal/testartifacts"
	"github.com/gittuf/gittuf/internal/tuf"
	tufv01 "github.com/gittuf/gittuf/internal/tuf/v01"
	"github.com/stretchr/testify/assert"
)

func TestInitializeTargets(t *testing.T) {
	rootSigner := setupSSHKeysForSigning(t, rootKeyBytes, rootPubKeyBytes)
	targetsSigner := setupSSHKeysForSigning(t, targetsKeyBytes, targetsPubKeyBytes)

	targetsKey := tufv01.NewKeyFromSSLibKey(targetsSigner.MetadataKey())

	t.Run("successful initialization", func(t *testing.T) {
		// The helper also runs InitializeTargets for this test
		r := createTestRepositoryWithRoot(t, "")

		if err := r.AddTopLevelTargetsKey(testCtx, rootSigner, targetsKey, false); err != nil {
			t.Fatal(err)
		}

		if err := r.InitializeTargets(testCtx, targetsSigner, policy.TargetsRoleName, false); err != nil {
			t.Fatal(err)
		}

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		assert.Contains(t, targetsMetadata.GetRules(), tufv01.AllowRule())
	})

	t.Run("invalid role name", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		if err := r.AddTopLevelTargetsKey(testCtx, rootSigner, targetsKey, false); err != nil {
			t.Fatal(err)
		}

		err := r.InitializeTargets(testCtx, targetsSigner, policy.RootRoleName, false)
		assert.ErrorIs(t, err, ErrInvalidPolicyName)
	})
}

func TestAddDelegation(t *testing.T) {
	targetsSigner := setupSSHKeysForSigning(t, targetsKeyBytes, targetsPubKeyBytes)

	t.Run("valid rule / delegation name", func(t *testing.T) {
		r := createTestRepositoryWithPolicy(t, "")

		targetsPubKey := tufv01.NewKeyFromSSLibKey(targetsSigner.MetadataKey())

		ruleName := "test-rule"
		authorizedKeys := []tuf.Principal{targetsPubKey}
		rulePatterns := []string{"git:branch=main"}

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		gpgKey, err := gpg.LoadGPGKeyFromBytes(gpgPubKeyBytes)
		if err != nil {
			t.Fatal(err)
		}

		targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(targetsMetadata.GetPrincipals()))
		assert.Equal(t, 2, len(targetsMetadata.GetRules()))
		assert.Contains(t, targetsMetadata.GetRules(), tufv01.AllowRule())

		if err := r.AddPrincipalToTargets(testCtx, targetsSigner, policy.TargetsRoleName, authorizedKeys, false); err != nil {
			t.Fatal(err)
		}

		err = r.AddDelegation(testCtx, targetsSigner, policy.TargetsRoleName, ruleName, []string{targetsPubKey.KeyID}, rulePatterns, 1, false)
		assert.Nil(t, err)

		state, err = policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		targetsMetadata, err = state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		assert.Contains(t, targetsMetadata.GetPrincipals(), targetsPubKey.ID())
		assert.Contains(t, targetsMetadata.GetPrincipals(), gpgKey.KeyID)
		assert.Equal(t, 2, len(targetsMetadata.GetPrincipals()))
		assert.Equal(t, 3, len(targetsMetadata.GetRules()))
		assert.Contains(t, targetsMetadata.GetRules(), &tufv01.Delegation{
			Name:        ruleName,
			Paths:       rulePatterns,
			Terminating: false,
			Role:        tufv01.Role{KeyIDs: set.NewSetFromItems(targetsPubKey.KeyID), Threshold: 1},
		})
		assert.Contains(t, targetsMetadata.GetRules(), tufv01.AllowRule())
	})

	t.Run("invalid rule name", func(t *testing.T) {
		r := createTestRepositoryWithPolicy(t, "")

		err := r.AddDelegation(testCtx, targetsSigner, policy.TargetsRoleName, policy.RootRoleName, nil, nil, 1, false)
		assert.ErrorIs(t, err, ErrInvalidPolicyName)
	})
}

func TestUpdateDelegation(t *testing.T) {
	r := createTestRepositoryWithPolicy(t, "")

	targetsSigner := setupSSHKeysForSigning(t, targetsKeyBytes, targetsPubKeyBytes)

	gpgKeyR, err := gpg.LoadGPGKeyFromBytes(gpgKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	gpgKey := tufv01.NewKeyFromSSLibKey(gpgKeyR)
	targetsKey := tufv01.NewKeyFromSSLibKey(targetsSigner.MetadataKey())

	if err := r.AddPrincipalToTargets(testCtx, targetsSigner, policy.TargetsRoleName, []tuf.Principal{gpgKey, targetsKey}, false); err != nil {
		t.Fatal(err)
	}

	err = r.UpdateDelegation(testCtx, targetsSigner, policy.TargetsRoleName, "protect-main", []string{gpgKey.KeyID, targetsKey.KeyID}, []string{"git:refs/heads/main"}, 1, false)
	assert.Nil(t, err)

	state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
	if err != nil {
		t.Fatal(err)
	}

	targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 2, len(targetsMetadata.GetRules()))
	assert.Contains(t, targetsMetadata.GetRules(), &tufv01.Delegation{
		Name:        "protect-main",
		Paths:       []string{"git:refs/heads/main"},
		Terminating: false,
		Role:        tufv01.Role{KeyIDs: set.NewSetFromItems(gpgKey.KeyID, targetsKey.KeyID), Threshold: 1},
	})
}

func TestReorderDelegations(t *testing.T) {
	targetsSigner := setupSSHKeysForSigning(t, targetsKeyBytes, targetsPubKeyBytes)
	targetsKey := tufv01.NewKeyFromSSLibKey(targetsSigner.MetadataKey())

	r := createTestRepositoryWithPolicy(t, "")

	if err := r.AddPrincipalToTargets(testCtx, targetsSigner, policy.TargetsRoleName, []tuf.Principal{targetsKey}, false); err != nil {
		t.Fatal(err)
	}

	ruleNames := []string{"rule-1", "rule-2", "rule-3"}
	for _, ruleName := range ruleNames {
		err := r.AddDelegation(testCtx, targetsSigner, policy.TargetsRoleName, ruleName, []string{targetsKey.KeyID}, []string{ruleName}, 1, false)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Valid Input
	newOrder := []string{"rule-3", "rule-1", "rule-2", "protect-main"}
	err := r.ReorderDelegations(testCtx, targetsSigner, policy.TargetsRoleName, newOrder, false)
	if err != nil {
		t.Fatal(err)
	}

	state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
	if err != nil {
		t.Fatal(err)
	}
	targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
	if err != nil {
		t.Fatal(err)
	}

	finalOrder := []string{}
	for _, role := range targetsMetadata.GetRules() {
		finalOrder = append(finalOrder, role.ID())
	}
	expectedFinalOrder := append([]string{}, newOrder...)
	expectedFinalOrder = append(expectedFinalOrder, tuf.AllowRuleName)
	assert.Equal(t, expectedFinalOrder, finalOrder)
}

func TestRemoveDelegation(t *testing.T) {
	r := createTestRepositoryWithPolicy(t, "")

	targetsSigner := setupSSHKeysForSigning(t, targetsKeyBytes, targetsPubKeyBytes)
	targetsPubKey := tufv01.NewKeyFromSSLibKey(targetsSigner.MetadataKey())

	ruleName := "test-rule"
	authorizedKeys := []tuf.Principal{targetsPubKey}
	rulePatterns := []string{"git:branch=main"}

	if err := r.AddPrincipalToTargets(testCtx, targetsSigner, policy.TargetsRoleName, authorizedKeys, false); err != nil {
		t.Fatal(err)
	}

	err := r.AddDelegation(testCtx, targetsSigner, policy.TargetsRoleName, ruleName, []string{targetsPubKey.KeyID}, rulePatterns, 1, false)
	assert.Nil(t, err)

	state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
	if err != nil {
		t.Fatal(err)
	}

	targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
	assert.Nil(t, err)
	assert.Contains(t, targetsMetadata.GetPrincipals(), targetsPubKey.ID())
	assert.Equal(t, 3, len(targetsMetadata.GetRules()))
	assert.Contains(t, targetsMetadata.GetRules(), &tufv01.Delegation{
		Name:        ruleName,
		Paths:       rulePatterns,
		Terminating: false,
		Role:        tufv01.Role{KeyIDs: set.NewSetFromItems(targetsPubKey.KeyID), Threshold: 1},
	})
	assert.Contains(t, targetsMetadata.GetRules(), tufv01.AllowRule())

	err = r.RemoveDelegation(testCtx, targetsSigner, policy.TargetsRoleName, ruleName, false)
	assert.Nil(t, err)

	state, err = policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
	if err != nil {
		t.Fatal(err)
	}

	targetsMetadata, err = state.GetTargetsMetadata(policy.TargetsRoleName, false)
	assert.Nil(t, err)
	assert.Contains(t, targetsMetadata.GetPrincipals(), targetsPubKey.ID())
	assert.Equal(t, 2, len(targetsMetadata.GetRules()))
	assert.Contains(t, targetsMetadata.GetRules(), tufv01.AllowRule())
}

func TestAddPrincipalToTargets(t *testing.T) {
	r := createTestRepositoryWithPolicy(t, "")

	targetsSigner := setupSSHKeysForSigning(t, targetsKeyBytes, targetsPubKeyBytes)
	targetsPubKey := tufv01.NewKeyFromSSLibKey(targetsSigner.MetadataKey())

	gpgKeyR, err := gpg.LoadGPGKeyFromBytes(gpgPubKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	gpgKey := tufv01.NewKeyFromSSLibKey(gpgKeyR)

	authorizedKeysBytes := []tuf.Principal{targetsPubKey, gpgKey}

	state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
	if err != nil {
		t.Fatal(err)
	}

	targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
	assert.Nil(t, err)
	assert.Contains(t, targetsMetadata.GetPrincipals(), gpgKey.KeyID)
	assert.Equal(t, 1, len(targetsMetadata.GetPrincipals()))

	err = r.AddPrincipalToTargets(testCtx, targetsSigner, policy.TargetsRoleName, authorizedKeysBytes, false)
	assert.Nil(t, err)

	state, err = policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
	if err != nil {
		t.Fatal(err)
	}

	targetsMetadata, err = state.GetTargetsMetadata(policy.TargetsRoleName, false)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(targetsMetadata.GetPrincipals()))
}

func TestRemovePrincicpalFromTargets(t *testing.T) {
	r := createTestRepositoryWithPolicy(t, "")

	targetsSigner := setupSSHKeysForSigning(t, targetsKeyBytes, targetsPubKeyBytes)
	targetsPubKey := tufv01.NewKeyFromSSLibKey(targetsSigner.MetadataKey())

	gpgKeyR, err := gpg.LoadGPGKeyFromBytes(gpgPubKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	gpgKey := tufv01.NewKeyFromSSLibKey(gpgKeyR)

	authorizedKeysBytes := []tuf.Principal{targetsPubKey, gpgKey}

	err = r.AddPrincipalToTargets(testCtx, targetsSigner, policy.TargetsRoleName, authorizedKeysBytes, false)
	assert.Nil(t, err)

	state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
	if err != nil {
		t.Fatal(err)
	}

	targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(targetsMetadata.GetPrincipals()))

	err = r.RemovePrincipalFromTargets(testCtx, targetsSigner, policy.TargetsRoleName, targetsPubKey.ID(), false)
	assert.Nil(t, err)

	state, err = policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
	if err != nil {
		t.Fatal(err)
	}

	targetsMetadata, err = state.GetTargetsMetadata(policy.TargetsRoleName, false)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(targetsMetadata.GetPrincipals()))
	assert.Contains(t, targetsMetadata.GetPrincipals(), gpgKey.KeyID)
}

func TestSignTargets(t *testing.T) {
	r := createTestRepositoryWithPolicy(t, "")

	// Add root key as a targets key
	rootSigner := setupSSHKeysForSigning(t, rootKeyBytes, rootPubKeyBytes)
	rootPubKey := tufv01.NewKeyFromSSLibKey(rootSigner.MetadataKey())

	if err := r.AddTopLevelTargetsKey(testCtx, rootSigner, rootPubKey, false); err != nil {
		t.Fatal(err)
	}

	// Add signature to targets
	err := r.SignTargets(testCtx, rootSigner, policy.TargetsRoleName, false)
	assert.Nil(t, err)

	state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 2, len(state.TargetsEnvelope.Signatures))
}

func TestAddHook(t *testing.T) {
	t.Setenv(dev.DevModeKey, "1")

	targetsSigner := setupSSHKeysForSigning(t, targetsKeyBytes, targetsPubKeyBytes)
	targetsPubKey := tufv01.NewKeyFromSSLibKey(targetsSigner.MetadataKey())

	tmpDir := t.TempDir()

	hookPath := filepath.Join(tmpDir, "hello.lua")
	if err := os.WriteFile(hookPath, artifacts.SampleHookScript, 0o500); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	t.Run("valid pre-commit hook", func(t *testing.T) {
		r := createTestRepositoryWithPolicy(t, "")

		hookStage := "pre-commit"
		hookName := "test-hook"
		environment := "lua"
		modules := []string{}
		principals := []string{targetsPubKey.KeyID}

		hookBytes, err := os.ReadFile(hookPath)
		if err != nil {
			t.Fatal(err)
		}

		hookHash, err := r.r.WriteBlob(hookBytes)
		if err != nil {
			t.Fatal(err)
		}

		sha256Hash := sha256.New()
		sha256Hash.Write(hookBytes)
		sha256HashSum := sha256Hash.Sum(nil)

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		hooks, err := targetsMetadata.GetHooks("pre-commit")
		assert.Nil(t, err)
		assert.Equal(t, 0, len(hooks))

		if err := r.AddPrincipalToTargets(testCtx, targetsSigner, policy.TargetsRoleName, []tuf.Principal{targetsPubKey}, false); err != nil {
			t.Fatal(err)
		}

		err = r.AddHook(testCtx, targetsSigner, policy.TargetsRoleName, hookName, hookPath, hookStage, environment, modules, principals, true)
		assert.Nil(t, err)

		state, err = policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		targetsMetadata, err = state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		hooks, err = targetsMetadata.GetHooks("pre-commit")
		assert.Nil(t, err)
		assert.Equal(t, hooks["test-hook"], &tufv01.Hook{
			Name:         hookName,
			PrincipalIDs: set.NewSetFromItems(targetsPubKey.KeyID),
			Hashes:       map[string]gitinterface.Hash{"sha1": hookHash, "sha256": sha256HashSum},
			Environment:  "lua",
			Modules:      []string{},
		})
	})

	t.Run("valid pre-push hook", func(t *testing.T) {
		r := createTestRepositoryWithPolicy(t, "")

		hookStage := "pre-push"
		hookName := "test-hook"
		environment := "lua"
		modules := []string{}
		principals := []string{targetsPubKey.KeyID}

		hookBytes, err := os.ReadFile(hookPath)
		if err != nil {
			t.Fatal(err)
		}

		hookHash, err := r.r.WriteBlob(hookBytes)
		if err != nil {
			t.Fatal(err)
		}

		sha256Hash := sha256.New()
		sha256Hash.Write(hookBytes)
		sha256HashSum := sha256Hash.Sum(nil)

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		hooks, err := targetsMetadata.GetHooks("pre-push")
		assert.Nil(t, err)
		assert.Equal(t, 0, len(hooks))

		if err := r.AddPrincipalToTargets(testCtx, targetsSigner, policy.TargetsRoleName, []tuf.Principal{targetsPubKey}, false); err != nil {
			t.Fatal(err)
		}

		err = r.AddHook(testCtx, targetsSigner, policy.TargetsRoleName, hookName, hookPath, hookStage, environment, modules, principals, true)
		assert.Nil(t, err)

		state, err = policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		targetsMetadata, err = state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		hooks, err = targetsMetadata.GetHooks("pre-push")
		assert.Nil(t, err)
		assert.Equal(t, hooks["test-hook"], &tufv01.Hook{
			Name:         hookName,
			PrincipalIDs: set.NewSetFromItems(targetsPubKey.KeyID),
			Hashes:       map[string]gitinterface.Hash{"sha1": hookHash, "sha256": sha256HashSum},
			Environment:  "lua",
			Modules:      []string{},
		})
	})

	t.Run("invalid hook stage", func(t *testing.T) {
		r := createTestRepositoryWithPolicy(t, "")

		hookStage := "invalid-stage"
		hookName := "test-hook"
		environment := "lua"
		modules := []string{}
		principals := []string{targetsPubKey.KeyID}

		if err := r.AddPrincipalToTargets(testCtx, targetsSigner, policy.TargetsRoleName, []tuf.Principal{targetsPubKey}, false); err != nil {
			t.Fatal(err)
		}

		err := r.AddHook(testCtx, targetsSigner, policy.TargetsRoleName, hookName, hookPath, hookStage, environment, modules, principals, true)
		assert.ErrorIs(t, err, tuf.ErrInvalidHookStage)

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		hooks, err := targetsMetadata.GetHooks("pre-commit")
		assert.Nil(t, err)
		assert.Equal(t, 0, len(hooks))
	})
}

func TestRemoveHook(t *testing.T) {
	t.Setenv(dev.DevModeKey, "1")

	targetsSigner := setupSSHKeysForSigning(t, targetsKeyBytes, targetsPubKeyBytes)
	targetsPubKey := tufv01.NewKeyFromSSLibKey(targetsSigner.MetadataKey())

	tmpDir := t.TempDir()

	hookPath := filepath.Join(tmpDir, "hello.lua")
	if err := os.WriteFile(hookPath, artifacts.SampleHookScript, 0o500); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	t.Run("valid pre-commit hook", func(t *testing.T) {
		r := createTestRepositoryWithPolicy(t, "")

		hookStage := "pre-commit"
		hookName := "test-hook"
		environment := "lua"
		modules := []string{}
		principals := []string{targetsPubKey.KeyID}

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		// Check that there are no hooks present
		targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		hooks, err := targetsMetadata.GetHooks(hookStage)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(hooks))

		// Add hook
		if err := r.AddPrincipalToTargets(testCtx, targetsSigner, policy.TargetsRoleName, []tuf.Principal{targetsPubKey}, false); err != nil {
			t.Fatal(err)
		}
		if err := r.AddHook(testCtx, targetsSigner, policy.TargetsRoleName, hookName, hookPath, hookStage, environment, modules, principals, true); err != nil {
			t.Fatal(err)
		}
		state, err = policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		// Check for hook
		targetsMetadata, err = state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		hooks, err = targetsMetadata.GetHooks(hookStage)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(hooks))

		// Remove hook
		err = r.RemoveHook(testCtx, targetsSigner, policy.TargetsRoleName, hookName, hookStage, false)
		assert.Nil(t, err)

		// Check that the hook was removed
		state, err = policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}
		targetsMetadata, err = state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		hooks, err = targetsMetadata.GetHooks(hookStage)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(hooks))
	})

	t.Run("valid pre-push hook", func(t *testing.T) {
		r := createTestRepositoryWithPolicy(t, "")

		hookStage := "pre-push"
		hookName := "test-hook"
		environment := "lua"
		modules := []string{}
		principals := []string{targetsPubKey.KeyID}

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		// Check that there are no hooks present
		targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		hooks, err := targetsMetadata.GetHooks(hookStage)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(hooks))

		// Add hook
		if err := r.AddPrincipalToTargets(testCtx, targetsSigner, policy.TargetsRoleName, []tuf.Principal{targetsPubKey}, false); err != nil {
			t.Fatal(err)
		}
		if err := r.AddHook(testCtx, targetsSigner, policy.TargetsRoleName, hookName, hookPath, hookStage, environment, modules, principals, true); err != nil {
			t.Fatal(err)
		}
		state, err = policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}

		// Check for hook
		targetsMetadata, err = state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		hooks, err = targetsMetadata.GetHooks(hookStage)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(hooks))

		// Remove hook
		err = r.RemoveHook(testCtx, targetsSigner, policy.TargetsRoleName, hookName, hookStage, false)
		assert.Nil(t, err)

		// Check that the hook was removed
		state, err = policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef)
		if err != nil {
			t.Fatal(err)
		}
		targetsMetadata, err = state.GetTargetsMetadata(policy.TargetsRoleName, false)
		assert.Nil(t, err)
		hooks, err = targetsMetadata.GetHooks(hookStage)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(hooks))
	})

	t.Run("invalid hook stage", func(t *testing.T) {
		r := createTestRepositoryWithPolicy(t, "")

		hookStage := "invalid-stage"
		hookName := "test-hook"

		err := r.RemoveHook(testCtx, targetsSigner, policy.TargetsRoleName, hookName, hookStage, false)
		assert.ErrorIs(t, err, tuf.ErrInvalidHookStage)
	})
}
