# v0.1.11 (2021-10-21)

- Create initial commit 
- Rename structs, move mods, refactor traits 
- Generalize dependencies with trait bounds 
- Rename unit test mods, add v2localheader struct 
- Refactor entire project 
- Add all 9 shared key test vector cases 
- Rename some structs and complete minor edits 
- Add strongly typed claims 
- Refactor arbitrary claim to use try_from trait 
- Tighten up arbitrary claim api 
- Rename claim structs and fix lifetime issues 
- Refactor most structs to generics 
- Update readme 
- Update minor version in Cargo.toml 
- Touch cargo.toml to test git editor 
- Repair the readme file from a poor merge 

### Notes
    
- Not quite encrypting correctly.  Working on getting the first test vector to pass.

- Message struct renamed to Payload, moved around mods and refactored
  conversion traits.

- Generalizing some dependencies by using trait bounds in several methods and trait implementations

- Unit test mods were renamed for consistency

- Went nuts and did a big refactor, traits, eliminated a struct or two, some other thing. :-| all good, tests passing, code looks pretty good.

- All tests pass after addition.

- Renamed V2LocalDecryptedString to V2LocalDecryptedToken and a couple minor edits

- Still need to json serialize them properly after this commit

- Refactored arbitrary claim to use try_from trait instead of custom try_new for api consistency

- Tightened up arbitrary claim api and removed unused comments, small refactors

- Renamed claim structs for consistency and fixed lifetime issues with borrowed strings

- Major refactor to change most structs to generics using version and purpose as arguments
  
  additional struct refactors to accept generic version and purpose types

- Update the project status in the readme file
  
  The PasetoBuilder and PasetoParser were incorrectly indicating that they
  were complete.  They have not been started as of yet.

- version update

- Wanted to make sure nvim was opening correctly so I can start tightening
  up commit messages

- - feature: Basic encryption and decryption
  
   - feature: Generic token building and parsing
  
   - feature: Flexible claim validation sans custom validation functions
  
   - feature: All v2.local [PASETO](https://github.com/paseto-standard/test-vectors/blob/master/v2.json) test vectors implemented and
     successfully passing
# v0.1.10..v0.1.13 (2021-10-22)

- Repair the readme file from a poor merge 
- Add optional closure for custom validation 
- Merge pull request #5 from rrrodzilla/claim_validation_issue_1 
- Add chrono to Cargo and add paseto_builder (#10)

### Notes
    
- - feature: Basic encryption and decryption
  
   - feature: Generic token building and parsing
  
   - feature: Flexible claim validation sans custom validation functions
  
   - feature: All v2.local [PASETO](https://github.com/paseto-standard/test-vectors/blob/master/v2.json) test vectors implemented and
     successfully passing

- Add optional closure for custom validation

### Additions
    
- Added an optional closure argument to the validate_claim method.
    To be used to allow the user to provide custom validation logic for a
    particular claim

- Added logic in the parse method to run custom validation closures
    if one is specified.  This means claim validators will verify the
    claim exists and verify the value matches what is expected.  If a
    custom closure is provided, the validator first checks the claim
    exists and then the value is provided to the closure for further
    validation by the end user.

- PasetoTokenParseError::InvalidClaimValueType(String) for claim
    values we try to convert to an invalid type

- PasetoTokenParseError::CustomClaimValidation for claims which
    fail in user provided custom validation closures

- Implement Default trait on all reserved claims so that they can
    be passed into custom validation closures

- Implement From(&str) for CustomClaim so that they can be passed
    into custom validation closures which always ignore passed in values
    when adding the claim to the validator

- Move chrono from dev dependencies to dependencies

- Added PasetoTokenBuilder in preparation for adding PASETO
    validation logic

- extend_claims method to GenericTokenBuilder
   : bump patch version 0.1.13
