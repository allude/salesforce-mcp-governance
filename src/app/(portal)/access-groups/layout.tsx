import { ViewTabs } from '@/components/shell/ViewTabs';

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <ViewTabs view="access-groups" />
      {children}
    </>
  );
}
