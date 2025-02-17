import NextAuth from "next-auth"
import GoogleProvider from "next-auth/providers/google"
import FacebookProvider from 'next-auth/providers/facebook';
import GitHubProvider from 'next-auth/providers/github';
// import LinkedInProvider from 'next-auth/providers/linkedin';
// import TwitterProvider from 'next-auth/providers/twitter';
// import InstagramProvider from 'next-auth/providers/instagram';
import { socialLoginAction } from "./actions/authActions";
import { BASE_ROUTE } from "./route";
 
export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }),
    FacebookProvider({
      clientId: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      authorization: {
        params: {
          scope: 'email,public_profile' // request email and public profile
        }
      }
    }),
    GitHubProvider({
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
    }),
    // LinkedInProvider({
    //   clientId: process.env.LINKEDIN_CLIENT_ID,
    //   clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
    // }),
    // TwitterProvider({
    //   clientId: process.env.TWITTER_CLIENT_ID,
    //   clientSecret: process.env.TWITTER_CLIENT_SECRET,
    // }),
    // InstagramProvider({
    //   clientId: process.env.INSTAGRAM_CLIENT_ID,
    //   clientSecret: process.env.INSTAGRAM_CLIENT_SECRET,
    // }),
  ],
  callbacks: {
    async signIn({ user, account, profile, email, credentials }) {
      // console.log('account', account);
      // console.log('user', user);
      // console.log('profile', profile);
      // console.log('email', email);
      // console.log('credentials', credentials);
      let result;
      if (account.provider === 'google') {
        result = await socialLoginAction("google-oauth2", account.access_token);
      };

      if (account.provider === 'facebook') {
        result = await socialLoginAction("facebook", account.access_token);
      };

      if (account.provider === 'github') {
        result = await socialLoginAction("github", account.access_token);
      };

      if (result?.error) {
        return `${BASE_ROUTE}/auth/login?error=${result.error}`;
      }

      return true;
    },
    async jwt({ token, account }) {
      if (account) {
        token.accessToken = account.access_token;
      };
      return token;
    },
    // Don't add anything else as the session is set by setSessionCookie using backend
  },
});