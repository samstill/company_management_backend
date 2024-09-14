# company/admin.py

from django.contrib import admin
from .models import Company, CompanyType, Department, DepartmentEmployee

class CompanyAdmin(admin.ModelAdmin):
    list_display = ('name', 'ceo', 'executive_director', 'company_type')
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # Allow managers and executive directors to see their own companies
        if request.user.is_manager():
            return qs.filter(ceo=request.user)
        elif request.user.is_executive_director():
            return qs.filter(executive_director=request.user)
        return qs

    def get_readonly_fields(self, request, obj=None):
        if request.user.is_executive_director():
            return ['ceo']  # Executive directors should not modify CEOs
        return super().get_readonly_fields(request, obj)

@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ['name', 'company_type', 'ceo', 'executive_director', 'founded_date']
    search_fields = ['name', 'company_type__name']
    list_filter = ['company_type']


@admin.register(CompanyType)
class CompanyTypeAdmin(admin.ModelAdmin):
    list_display = ['name']


@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ['name', 'company', 'manager']
    list_filter = ['company']
    search_fields = ['name', 'company__name']


@admin.register(DepartmentEmployee)
class DepartmentEmployeeAdmin(admin.ModelAdmin):
    list_display = ['employee', 'department', 'date_joined']
    search_fields = ['employee__user__username', 'department__name']
