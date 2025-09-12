import React, { useState, useEffect } from 'react'
import { usersAPI } from '../services/api'
import toast from 'react-hot-toast'
import { useForm } from 'react-hook-form'
import { 
  Search, 
  Filter, 
  Download, 
  UserCheck, 
  Mail, 
  Calendar,
  Edit,
  Trash2,
  Plus,
  X,
  Save,
  Shield,
  User as UserIcon
} from 'lucide-react'
import Modal from '../components/Modal'

interface User {
  _id: string
  firstName: string
  lastName: string
  email: string
  company: string
  role: string
  isEmailVerified: boolean
  isActive: boolean
  lastLogin?: string
  createdAt: string
}

interface UserForm {
  firstName: string
  lastName: string
  email: string
  company: string
  role: string
  isEmailVerified: boolean
  isActive: boolean
}

export default function Users() {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [filterRole, setFilterRole] = useState('all')
  const [filterVerified, setFilterVerified] = useState('all')
  const [filterActive, setFilterActive] = useState('all')
  const [currentPage, setCurrentPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [showModal, setShowModal] = useState(false)
  const [editingUser, setEditingUser] = useState<User | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const { register, handleSubmit, formState: { errors }, reset, setValue } = useForm<UserForm>()

  useEffect(() => {
    loadUsers()
  }, [currentPage])

  const loadUsers = async () => {
    try {
      const response = await usersAPI.getAllUsers(currentPage, 20)
      if (response.data.success) {
        setUsers(response.data.data.users)
        setTotalPages(response.data.data.pagination.pages)
      }
    } catch (error: any) {
      toast.error('Failed to load users')
    } finally {
      setLoading(false)
    }
  }

  const openEditModal = (user: User) => {
    setEditingUser(user)
    const nameParts = user.name.split(' ')
    setValue('firstName', nameParts[0] || '')
    setValue('lastName', nameParts.slice(1).join(' ') || '')
    setValue('email', user.email)
    setValue('company', user.company_name || user.company)
    setValue('role', user.role)
    setValue('isEmailVerified', user.is_email_verified)
    setValue('isActive', user.is_active)
    setShowModal(true)
  }

  const closeModal = () => {
    setShowModal(false)
    setEditingUser(null)
    reset()
  }

  const onSubmit = async (data: UserForm) => {
    if (!editingUser) return
    
    setSubmitting(true)
    try {
      // Update user profile
      await usersAPI.updateUser(editingUser.id, {
        firstName: data.firstName,
        lastName: data.lastName,
        role: data.role,
        isEmailVerified: data.isEmailVerified,
        isActive: data.isActive
      })
      
      toast.success('User updated successfully')
      closeModal()
      loadUsers()
    } catch (error: any) {
      toast.error(error.response?.data?.message || 'Failed to update user')
    } finally {
      setSubmitting(false)
    }
  }

  const deleteUser = async (userId: string, userName: string) => {
    if (!confirm(`Are you sure you want to delete ${userName}? This action cannot be undone.`)) {
      return
    }

    try {
      await usersAPI.deleteUser(userId)
      toast.success('User deleted successfully')
      loadUsers()
    } catch (error: any) {
      toast.error('Failed to delete user')
    }
  }

  const filteredUsers = users.filter(user => {
    const matchesSearch = 
      user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (user.company_name || user.company || '').toLowerCase().includes(searchTerm.toLowerCase())
    
    const matchesRole = filterRole === 'all' || user.role === filterRole
    const matchesVerified = filterVerified === 'all' || 
      (filterVerified === 'verified' && user.is_email_verified) ||
      (filterVerified === 'unverified' && !user.is_email_verified)
    const matchesActive = filterActive === 'all' ||
      (filterActive === 'active' && user.is_active) ||
      (filterActive === 'inactive' && !user.is_active)
    
    return matchesSearch && matchesRole && matchesVerified && matchesActive
  })

  const exportUsers = () => {
    const csvContent = [
      ['Name', 'Email', 'Company', 'Role', 'Verified', 'Active', 'Last Login', 'Created'],
      ...filteredUsers.map(user => [
        user.name,
        user.email,
        user.company_name || user.company,
        user.role,
        user.is_email_verified ? 'Yes' : 'No',
        user.is_active ? 'Yes' : 'No',
        user.last_login_time ? new Date(user.last_login_time).toLocaleDateString() : 'Never',
        user.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'
      ])
    ].map(row => row.join(',')).join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'users-export.csv'
    a.click()
    window.URL.revokeObjectURL(url)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-4xl font-bold text-gray-900 mb-2">Users Management</h1>
          <p className="text-gray-600 text-lg">Manage all registered users and their permissions</p>
        </div>
        <button onClick={exportUsers} className="btn-secondary">
          <Download className="w-4 h-4 mr-2" />
          Export CSV
        </button>
      </div>

      {/* Enhanced Filters */}
      <div className="bg-white rounded-2xl shadow-sm border border-gray-200 p-6">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
            <input
              type="text"
              placeholder="Search users..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input-field pl-10"
            />
          </div>
          
          <select
            value={filterRole}
            onChange={(e) => setFilterRole(e.target.value)}
            className="input-field"
          >
            <option value="all">All Roles</option>
            <option value="user">Users</option>
            <option value="admin">Admins</option>
          </select>
          
          <select
            value={filterVerified}
            onChange={(e) => setFilterVerified(e.target.value)}
            className="input-field"
          >
            <option value="all">All Verification</option>
            <option value="verified">Verified</option>
            <option value="unverified">Unverified</option>
          </select>

          <select
            value={filterActive}
            onChange={(e) => setFilterActive(e.target.value)}
            className="input-field"
          >
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
          
          <button onClick={loadUsers} className="btn-primary">
            <Filter className="w-4 h-4 mr-2" />
            Refresh
          </button>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  User
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Company
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Role
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Last Login
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredUsers.map((user) => (
                <tr key={user._id} className="table-row">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="w-12 h-12 bg-gradient-to-br from-blue-400 to-blue-500 rounded-xl flex items-center justify-center shadow-sm">
                        <span className="text-white font-semibold text-sm">
                          {user.name.split(' ').map((n: string) => n[0]).join('').substring(0, 2)}
                        </span>
                      </div>
                      <div className="ml-4">
                        <div className="text-sm font-semibold text-gray-900">
                          {user.name}
                        </div>
                        <div className="text-sm text-gray-500">{user.email}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {user.company_name || user.company}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${
                      user.role === 'admin' 
                        ? 'bg-purple-100 text-purple-800' 
                        : 'bg-gray-100 text-gray-800'
                    }`}>
                      {user.role === 'admin' ? <Shield className="w-3 h-3 mr-1" /> : <UserIcon className="w-3 h-3 mr-1" />}
                      {user.role}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      {user.is_email_verified ? (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                          <UserCheck className="w-3 h-3 mr-1" />
                          Verified
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                          <Mail className="w-3 h-3 mr-1" />
                          Pending
                        </span>
                      )}
                      {!user.is_active && (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                          Inactive
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {user.last_login_time ? (
                      <div className="flex items-center">
                        <Calendar className="w-4 h-4 mr-1" />
                        {new Date(user.last_login_time).toLocaleDateString()}
                      </div>
                    ) : (
                      'Never'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => openEditModal(user)}
                        className="p-2 text-blue-600 hover:text-blue-800 hover:bg-blue-50 rounded-lg transition-colors"
                        title="Edit user"
                      >
                        <Edit className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => deleteUser(user.id, user.name)}
                        className="p-2 text-red-600 hover:text-red-800 hover:bg-red-50 rounded-lg transition-colors"
                        title="Delete user"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between bg-gray-50">
            <div className="text-sm text-gray-700">
              Showing page {currentPage} of {totalPages} ({filteredUsers.length} users)
            </div>
            <div className="flex space-x-2">
              <button
                onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                disabled={currentPage === 1}
                className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <button
                onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                disabled={currentPage === totalPages}
                className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {filteredUsers.length === 0 && !loading && (
        <div className="bg-white rounded-2xl shadow-sm border border-gray-200 p-12 text-center">
          <UserIcon className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900">No users found</h3>
          <p className="mt-1 text-sm text-gray-500">
            {searchTerm ? 'Try adjusting your search criteria.' : 'No users have registered yet.'}
          </p>
        </div>
      )}

      {/* Edit User Modal */}
      <Modal isOpen={showModal} onClose={closeModal} title="Edit User">
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                First Name *
              </label>
              <input
                {...register('firstName', { required: 'First name is required' })}
                className="input-field"
                placeholder="Enter first name"
              />
              {errors.firstName && (
                <p className="mt-1 text-sm text-red-600">{errors.firstName.message}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Last Name *
              </label>
              <input
                {...register('lastName', { required: 'Last name is required' })}
                className="input-field"
                placeholder="Enter last name"
              />
              {errors.lastName && (
                <p className="mt-1 text-sm text-red-600">{errors.lastName.message}</p>
              )}
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Email *
            </label>
            <input
              {...register('email', { 
                required: 'Email is required',
                pattern: {
                  value: /^\S+@\S+$/i,
                  message: 'Invalid email address'
                }
              })}
              type="email"
              className="input-field"
              placeholder="Enter email address"
            />
            {errors.email && (
              <p className="mt-1 text-sm text-red-600">{errors.email.message}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Company *
            </label>
            <input
              {...register('company', { required: 'Company is required' })}
              className="input-field"
              placeholder="Enter company name"
            />
            {errors.company && (
              <p className="mt-1 text-sm text-red-600">{errors.company.message}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Role *
            </label>
            <select
              {...register('role', { required: 'Role is required' })}
              className="input-field"
            >
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
            {errors.role && (
              <p className="mt-1 text-sm text-red-600">{errors.role.message}</p>
            )}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="flex items-center">
              <input
                {...register('isEmailVerified')}
                type="checkbox"
                className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
              />
              <label className="ml-2 block text-sm text-gray-900">
                Email Verified
              </label>
            </div>

            <div className="flex items-center">
              <input
                {...register('isActive')}
                type="checkbox"
                className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
              />
              <label className="ml-2 block text-sm text-gray-900">
                Account Active
              </label>
            </div>
          </div>

          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={closeModal}
              className="btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="btn-primary disabled:opacity-50"
            >
              {submitting ? (
                <div className="flex items-center">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Updating...
                </div>
              ) : (
                <>
                  <Save className="w-4 h-4 mr-2" />
                  Update User
                </>
              )}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  )
}