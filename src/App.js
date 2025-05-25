import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import ReCAPTCHA from 'react-google-recaptcha';
import { Eye, EyeOff, User, Lock, Mail, ArrowRight, Check } from 'lucide-react';
import './App.css';
import { Amplify } from 'aws-amplify';
import { signIn, signUp, confirmSignIn, confirmSignUp } from 'aws-amplify/auth';

Amplify.configure({
  Auth: {
    Cognito: {
      userPoolId: process.env.REACT_APP_POOLID,
      userPoolClientId: process.env.REACT_APP_POOL_CLIENT_ID,
      signUpVerificationMethod: 'link',
      loginWith: {
        oauth: {
          scopes: [
            'phone',
            'email',
            'profile',
            'openid',
            'clientMetaData',
            'aws.cognito.signin.user.admin'
          ],
          redirectSignIn: ['http://localhost:3000/'],
          redirectSignOut: ['http://localhost:3000/'],
          responseType: 'code'
        }
      }
    }
  }
});

export default function App() {
  const navigate = useNavigate();
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [recaptchaToken, setRecaptchaToken] = useState(null);

  const [isConfirmStep, setIsConfirmStep] = useState(false);
  const [confirmationCode, setConfirmationCode] = useState('');
  const [usernameToConfirm, setUsernameToConfirm] = useState('');

  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
    setError('');
  };

  const handleSignIn = async (e) => {
    if (e) e.preventDefault();
    if (!recaptchaToken) {
      setError('Please complete the reCAPTCHA verification');
      return;
    }

    const { username, password } = formData;
    if (!username || !password) {
      setError('Username and password are required');
      return;
    }

    setIsLoading(true);
    try {
      const { isSignedIn, nextStep } = await signIn({
        username,
        password,
        options: { authFlowType: 'CUSTOM_WITH_SRP' }
      });

      if (nextStep.signInStep === 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE') {
        const challengeResponse = recaptchaToken;
        const { isSignedIn: afterCaptcha, nextStep: afterCaptchaStep } = await confirmSignIn({ challengeResponse });

        if (afterCaptcha && afterCaptchaStep.signInStep === 'DONE') {
          setSuccess('Sign in successful! Redirecting to dashboard...');
          setTimeout(() => navigate('/signout'), 1500);
        } else if (afterCaptchaStep.signInStep === 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE') {
          const challengeParameters = afterCaptchaStep.additionalInfo;
          const tosContent = challengeParameters.tos;
          navigate('/terms-of-service', {
            state: {
              tosContent,
              challengeParameters
            }
          });
        } else {
          setError('reCaptcha validation failed');
          setSuccess('');
        }
      }
    } catch (err) {
      console.error(err);
      setError(err.message || 'Sign in failed');
    } finally {
      setIsLoading(false);
      setRecaptchaToken('');
    }
  };

  const handleSignUp = async (e) => {
    if (e) e.preventDefault();
    if (!recaptchaToken) {
      setError('Please complete the reCAPTCHA verification');
      return;
    }

    const { username, email, password, confirmPassword } = formData;
    if (!username || !email || !password) {
      setError('All fields are required');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch(`${process.env.REACT_APP_TOS_API_URL}/latest-hash`);
      const { tosHash } = await response.json();

      const { isSignedUp, nextStep } = await signUp({
        username,
        password,
        options: {
          userAttributes: { email },
          validationData: {
            token: recaptchaToken,
            tosHash: tosHash
          }
        }
      });

      if (nextStep.signUpStep === 'CONFIRM_SIGN_UP') {
        setSuccess('Verification code sent. Please confirm.');
        setIsConfirmStep(true);
        setUsernameToConfirm(username);
      } else {
        setSuccess('Successfully signed up. Please enter code to confirm.');
      }
      setError('');
    } catch (err) {
      console.error(err);
      setError(err.message || 'Sign up failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleConfirmSignUp = async (e) => {
    if (e) e.preventDefault();
    if (!confirmationCode) {
      setError('Please enter the verification code');
      return;
    }

    setIsLoading(true);
    try {
      const { isSignUpComplete } = await confirmSignUp({
        username: usernameToConfirm,
        confirmationCode
      });

      if (isSignUpComplete) {
        setSuccess('Account verified! You can now sign in.');
        setIsConfirmStep(false);
        setIsLogin(true);
      }
    } catch (err) {
      console.error(err);
      setError(err.message || 'Verification failed.');
    } finally {
      setIsLoading(false);
    }
  };

  const toggleAuthMode = () => {
    setIsLogin(!isLogin);
    setError('');
    setSuccess('');
    setIsConfirmStep(false);
    setConfirmationCode('');
    setFormData({ username: '', email: '', password: '', confirmPassword: '' });
  };

  const cancelConfirmation = () => {
    setIsConfirmStep(false);
    setConfirmationCode('');
    setError('');
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h2>
            {isConfirmStep ? 'Verify your account' : isLogin ? 'Sign in to your account' : 'Create a new account'}
          </h2>
          {!isConfirmStep && (
            <p>
              {isLogin ? "Don't have an account? " : "Already have an account? "}
              <button onClick={toggleAuthMode} className="text-link">
                {isLogin ? 'Sign up' : 'Sign in'}
              </button>
            </p>
          )}
        </div>

        {error && <div className="auth-message error">{error}</div>}
        {success && <div className="auth-message success">{success}</div>}

        <div className="auth-form">
          {isConfirmStep ? (
            <div className="form-fields">
              <div className="input-group">
                <div className="input-icon"><Check /></div>
                <input
                  name="confirmationCode"
                  type="text"
                  required
                  value={confirmationCode}
                  onChange={(e) => setConfirmationCode(e.target.value)}
                  placeholder="Enter verification code"
                />
              </div>
              <div className="form-actions">
                <button onClick={handleConfirmSignUp} className="submit-button" disabled={isLoading}>
                  {isLoading ? 'Processing...' : <>Verify Account <ArrowRight className="button-icon" /></>}
                </button>
                <button onClick={cancelConfirmation} className="text-link" style={{ marginTop: '10px' }}>
                  Go back
                </button>
              </div>
            </div>
          ) : (
            <>
              <div className="form-fields">
                <div className="input-group">
                  <div className="input-icon"><User /></div>
                  <input
                    name="username"
                    type="text"
                    required
                    value={formData.username}
                    onChange={handleInputChange}
                    placeholder="Username"
                  />
                </div>

                {!isLogin && (
                  <div className="input-group">
                    <div className="input-icon"><Mail /></div>
                    <input
                      name="email"
                      type="email"
                      required
                      value={formData.email}
                      onChange={handleInputChange}
                      placeholder="Email"
                    />
                  </div>
                )}

                <div className="input-group">
                  <div className="input-icon"><Lock /></div>
                  <input
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={formData.password}
                    onChange={handleInputChange}
                    placeholder="Password"
                  />
                  <button onClick={() => setShowPassword(!showPassword)} className="password-toggle">
                    {showPassword ? <EyeOff /> : <Eye />}
                  </button>
                </div>

                {!isLogin && (
                  <div className="input-group">
                    <div className="input-icon"><Lock /></div>
                    <input
                      name="confirmPassword"
                      type={showPassword ? 'text' : 'password'}
                      required
                      value={formData.confirmPassword}
                      onChange={handleInputChange}
                      placeholder="Confirm Password"
                    />
                  </div>
                )}

                <div className="recaptcha-container">
                  <ReCAPTCHA
                    sitekey={process.env.REACT_APP_SITE_KEY}
                    onChange={token => setRecaptchaToken(token)}
                    theme="light"
                  />
                </div>
              </div>
              <div className="form-actions">
                <button
                  onClick={isLogin ? handleSignIn : handleSignUp}
                  className="submit-button"
                  disabled={isLoading}
                >
                  {isLoading ? 'Processing...' : <>{isLogin ? 'Sign in' : 'Sign up'} <ArrowRight className="button-icon" /></>}
                </button>
              </div>
            </>
          )}
        </div>

        {isLogin && !isConfirmStep && (
          <div className="forgot-password">
            <button className="text-link">Forgot your password?</button>
          </div>
        )}
      </div>
    </div>
  );
}
