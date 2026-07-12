export default function ForbiddenPage() {
  return (
    <main className="dashboard-main">
      <h1>Access Denied</h1>
      <p>Your authenticated principal lacks RBAC permission for the requested module.</p>
    </main>
  );
}
