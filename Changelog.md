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
