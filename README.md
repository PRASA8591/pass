# Pass vault

This app uses Firebase Authentication and Cloud Firestore for login and vault data. The browser uses the supplied Firebase project configuration, and each user's entries live at `users/{uid}/entries/{entryId}`.

## Firebase setup

1. In Firebase Console, open project `mypassword-5e734`.
2. In Authentication, enable the **Email/Password** provider.
3. In Firestore Database, create the database in the region you want.
4. Install the Firebase CLI and sign in:

```sh
npm install -g firebase-tools
firebase login
firebase use mypassword-5e734
```

5. Publish the included rules and hosting configuration:

```sh
firebase deploy --only firestore:rules,hosting
```

The Firestore rules only allow an authenticated user to read or change entries below their own Firebase Auth UID. The app creates the first account from the **Create a vault** screen and converts the chosen username into a private Firebase Auth email identity.

Run locally with `npm start` and open `http://localhost:3000`.