# company/serializers.py

from rest_framework import serializers
from .models import Company, CompanyType, Department, DepartmentEmployee

class CompanyTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyType
        fields = ['id', 'name']


class CompanySerializer(serializers.ModelSerializer):
    company_type = CompanyTypeSerializer()

    class Meta:
        model = Company
        fields = ['id', 'name', 'company_type', 'ceo', 'executive_director', 'description', 'founded_date']


class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = ['id', 'name', 'company', 'manager', 'description']


class DepartmentEmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = DepartmentEmployee
        fields = ['id', 'employee', 'department', 'date_joined']
