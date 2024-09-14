from django.shortcuts import render

# Create your views here.
# company/views.py

from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from .models import Company, CompanyType, Department, DepartmentEmployee
from .serializers import CompanySerializer, DepartmentSerializer, DepartmentEmployeeSerializer

class CompanyListCreateView(generics.ListCreateAPIView):
    queryset = Company.objects.all()
    serializer_class = CompanySerializer
    permission_classes = [IsAuthenticated]


class DepartmentListCreateView(generics.ListCreateAPIView):
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        company_id = self.kwargs['company_id']
        return Department.objects.filter(company_id=company_id)


class DepartmentEmployeeListCreateView(generics.ListCreateAPIView):
    queryset = DepartmentEmployee.objects.all()
    serializer_class = DepartmentEmployeeSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        department_id = self.kwargs['department_id']
        return DepartmentEmployee.objects.filter(department_id=department_id)
