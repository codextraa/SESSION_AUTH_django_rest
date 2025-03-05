import styles from './page.module.css';

export default function Page() {
  return (
    <div className={styles.container}>
      <h1 className={styles.titleh1}>Welcome to SESSION-AUTH</h1>
      <p className={styles.description}>
        A fullstack web application built with <strong>NextJS</strong> for the frontend 
        and <strong>Django</strong> for the backend, utilizing <strong>REST</strong> APIs 
        and a <strong>Postgres</strong> database. This project demonstrates a secure 
        authentication system using <strong>Session-based authentication</strong>, 
        featuring OTP-based login, email verification based registration, email and phone 
        verification, password reset, and social media login integration. The application 
        starts with a login page where users enter their email and password. Upon successful 
        authentication, an OTP is sent to the user's email for verification. After verifying 
        the OTP, a session is established, and users receive a session ID and CSRF token for 
        accessing protected routes. The user can edit thier profile in the <strong>Profile
        </strong> page. The profile image is retrieved from social providers if the account 
        is created using social account. Otherwise a default image is set for password users.
      </p>
      <p className={styles.description}>
        <strong>Superusers</strong> and <strong>Admins</strong> have elevated priviliges where 
        they can access the <strong>Admin Dashboard</strong> and can activate, deactivate, 
        edit or delete an user according to thier priviliges.
      </p>
      <p className={styles.linkContainer}>
        For more details, visit the{' '}
        <a href="https://github.com/wasee-sun/SESSION_AUTH_django_rest" className={styles.githubLink}>
          GitHub repository
        </a>.
      </p>
    </div>
  );
}