import { Route, Routes } from 'react-router-dom'
import type { NavItem } from './NavigationRegistry'
import ProtectedRoute from './ProtectedRoute'
import AdminLayout from '../layout/AdminLayout'
import NotFoundPage from '../pages/NotFoundPage'

export default function AppRoutes({ items, moduleWarning = false }: { items: readonly NavItem[]; moduleWarning?: boolean }) {
  return <Routes>
    <Route element={<AdminLayout items={items} moduleWarning={moduleWarning} />}>
      {items.map((item) => item.path === '/'
        ? <Route key={item.path} index element={<ProtectedRoute item={item} />} />
        : <Route key={item.path} path={item.path} caseSensitive element={<ProtectedRoute item={item} />} />)}
      <Route path="*" element={<NotFoundPage />} />
    </Route>
  </Routes>
}
