#

## Account Linking (Existing Users Can Link Google Accounts)

This phase will allow:
1. **Existing email/password users** to link their Google accounts
2. **Google users** to set passwords for local login
3. **Account management** - view linked accounts, unlink accounts

### Key Features to Implement:

1. **Link Google Account to Existing User**
    - User logs in with email/password
    - User can link their Google account
    - Same email validation and conflict resolution

2. **Enhanced OAuth2 Flow**
    - If Google email matches existing local account, offer to link
    - Handle the linking process securely

3. **Account Management APIs**
    - View linked accounts
    - Unlink Google account
    - Set password for OAuth2-only users

4. **Updated User Experience**
    - Better error handling for email conflicts
    - Account linking confirmation flows

### Questions before we start Phase 2:

1. **Email Conflict Strategy**: When a Google user tries to register but email already exists with a local account, should we:
    - Block registration and show "email already exists" error?
    - Or offer to link the accounts (requires user to prove they own the local account)?

2. **Linking Security**: For account linking, should we:
    - Require the user to enter their current password?
    - Or just require them to be logged in?

3. **Primary Login Method**: When a user has both local and Google accounts linked:
    - Should they be able to use either method to login?
    - Any restrictions or preferences?

