import { Suspense } from 'react';
import { SignInPage } from '@/components/shell/SignInPage';

/** `/`: sign in (or go straight on when already signed in). The portal views live under (portal). */
export default function Page() {
  return (
    <Suspense fallback={null}>
      <SignInPage />
    </Suspense>
  );
}
