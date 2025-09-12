import React, { useState, useEffect } from 'react'
import { companiesAPI } from '../services/api'
import toast from 'react-hot-toast'
import { useForm } from 'react-hook-form'
import { 
  Building2, 
  Plus, 
  Edit, 
  Trash2, 
  Globe, 
  Mail, 
  Calendar,
  X,
  Check,
  Save,
  Eye,
  EyeOff
} from 'lucide-react'
import Modal from '../components/Modal'

interface Company {
  id: string
  name: string
  domain_name: string
  created_at: string
}

interface CompanyForm {
  name: string
  domain_name: string
}

export default function Companies() {
  const [companies, setCompanies] = useState<Company[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editingCompany, setEditingCompany] = useState<Company | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const { register, handleSubmit, formState: { errors }, reset, setValue } = useForm<CompanyForm>()

  useEffect(() => {
    loadCompanies()
  }, [])

  const loadCompanies = async () => {
    try {
      const response = await companiesAPI.getAllCompanies()
      if (response.data.success) {
        setCompanies(response.data.data.companies)
      }
    } catch (error: any) {
      toast.error('Failed to load companies')
    } finally {
      setLoading(false)
    }
  }

  const openModal = (company?: Company) => {
    if (company) {
      setEditingCompany(company)
      setValue('name', company.name)
      setValue('domain_name', company.domain_name)
    } else {
      setEditingCompany(null)
      reset()
    }
    setShowModal(true)
  }

  const closeModal = () => {
    setShowModal(false)
    setEditingCompany(null)
    reset()
  }

  const onSubmit = async (data: CompanyForm) => {
    setSubmitting(true)
    try {
      const companyData = {
        name: data.name,
        domain_name: data.domain_name,
        domains: [data.domain_name] // For compatibility
      }

      if (editingCompany) {
        await companiesAPI.updateCompany(editingCompany.id, companyData)
        toast.success('Company updated successfully')
      } else {
        await companiesAPI.createCompany(companyData)
        toast.success('Company created successfully')
      }
      
      closeModal()
      loadCompanies()
    } catch (error: any) {
      toast.error(error.response?.data?.message || 'Operation failed')
    } finally {
      setSubmitting(false)
    }
  }

  const deleteCompany = async (companyId: string, companyName: string) => {
    if (!confirm(`Are you sure you want to delete ${companyName}? This will prevent new user registrations from this company.`)) {
      return
    }

    try {
      await companiesAPI.deleteCompany(companyId)
      toast.success('Company deleted successfully')
      loadCompanies()
    } catch (error: any) {
      toast.error('Failed to delete company')
    }
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
          <h1 className="text-4xl font-bold text-gray-900 mb-2">Companies Management</h1>
          <p className="text-gray-600 text-lg">Manage approved companies and their domains</p>
        </div>
        <div className="flex items-center space-x-3">
          <button onClick={() => openModal()} className="btn-primary">
            <Plus className="w-4 h-4 mr-2" />
            Add Company
          </button>
        </div>
      </div>

      {/* Companies Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {companies.map((company) => (
          <div key={company.id} className="bg-white rounded-2xl shadow-sm border border-gray-200 p-6 hover:shadow-xl transition-all duration-300 transform hover:-translate-y-1 border-l-4 border-l-primary-500">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center flex-1">
                <div className="w-12 h-12 bg-gradient-to-br from-purple-400 to-purple-500 rounded-xl flex items-center justify-center shadow-lg">
                  <Building2 className="w-6 h-6 text-white" />
                </div>
                <div className="ml-3 flex-1 min-w-0">
                  <h3 className="text-lg font-bold text-gray-900 mb-1 truncate">{company.name}</h3>
                  <div className="flex items-center">
                    <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                      <Check className="w-3 h-3 mr-1" />
                      Active
                    </span>
                  </div>
                </div>
              </div>
              <div className="flex space-x-1">
                <button
                  onClick={() => openModal(company)}
                  className="p-2 text-blue-600 hover:text-blue-800 hover:bg-blue-50 rounded-lg transition-colors"
                  title="Edit company"
                >
                  <Edit className="w-4 h-4" />
                </button>
                <button
                  onClick={() => deleteCompany(company.id, company.name)}
                  className="p-2 text-red-600 hover:text-red-800 hover:bg-red-50 rounded-lg transition-colors"
                  title="Delete company"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex items-center text-sm text-gray-500">
                <Globe className="w-4 h-4 mr-2 text-blue-500" />
                <span className="font-medium">1 domain</span>
              </div>
              <div className="flex flex-wrap gap-1">
                <span className="inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-medium bg-blue-50 text-blue-700 border border-blue-200">
                  {company.domain_name}
                </span>
              </div>
              
              <div className="flex items-center text-sm text-gray-500">
                <Calendar className="w-4 h-4 mr-2 text-purple-500" />
                <span>Created {new Date(company.created_at).toLocaleDateString()}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {companies.length === 0 && (
        <div className="bg-white rounded-2xl shadow-sm border border-gray-200 p-12 text-center">
          <Building2 className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900">No companies found</h3>
          <p className="mt-1 text-sm text-gray-500">
            Get started by creating a new company.
          </p>
          <button onClick={() => openModal()} className="mt-4 btn-primary">
            <Plus className="w-4 h-4 mr-2" />
            Add Company
          </button>
        </div>
      )}

      {/* Company Modal */}
      <Modal isOpen={showModal} onClose={closeModal} title={editingCompany ? 'Edit Company' : 'Add New Company'}>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Company Name *
            </label>
            <input
              {...register('name', { required: 'Company name is required' })}
              className="input-field"
              placeholder="Enter company name"
            />
            {errors.name && (
              <p className="mt-1 text-sm text-red-600">{errors.name.message}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Domain *
            </label>
            <input
              {...register('domain_name', { required: 'Domain is required' })}
              className="input-field"
              placeholder="example.com"
            />
            {errors.domain_name && (
              <p className="mt-1 text-sm text-red-600">{errors.domain_name.message}</p>
            )}
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
                  {editingCompany ? 'Updating...' : 'Creating...'}
                </div>
              ) : (
                <>
                  <Save className="w-4 h-4 mr-2" />
                  {editingCompany ? 'Update Company' : 'Create Company'}
                </>
              )}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  )
}