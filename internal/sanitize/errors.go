//
//  Copyright 2026 The InfiniFlow Authors. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

package sanitize

import "errors"

// Sanitization errors. Their text is a stable code and nothing else: they
// never embed source text, matched values or matcher diagnostics (regexp2
// errors include the complete input, so they are never wrapped).
var (
	// ErrRulesUnavailable reports that the rule catalog could not be loaded,
	// validated or compiled.
	ErrRulesUnavailable = errors.New("SANITIZE_RULES_UNAVAILABLE")
	// ErrTimeout reports that matching exceeded the per-call regex timeout or
	// the caller's context deadline.
	ErrTimeout = errors.New("SANITIZE_TIMEOUT")
	// ErrResidual reports that a rule still matched after replacement.
	ErrResidual = errors.New("SANITIZE_RESIDUAL_DETECTED")
)
