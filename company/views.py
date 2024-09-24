from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import Company, Department, DepartmentEmployee
from .serializers import CompanySerializer, DepartmentSerializer, DepartmentEmployeeSerializer
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status

class CompanyViewSet(viewsets.ModelViewSet):
    queryset = Company.objects.all()
    serializer_class = CompanySerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['get'])
    def count(self, request):
        company_count = self.queryset.count()
        return Response({'count': company_count}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'])
    def trends(self, request):
        # Fake data for now
        fake_labels = ['January', 'February', 'March', 'April', 'May', 'June']
        fake_values = [10, 15, 20, 30, 35, 45]
        return Response({'labels': fake_labels, 'values': fake_values}, status=status.HTTP_200_OK)


class DepartmentViewSet(viewsets.ModelViewSet):
    serializer_class = DepartmentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        company_id = self.kwargs['company_id']
        return Department.objects.filter(company_id=company_id)


class DepartmentEmployeeViewSet(viewsets.ModelViewSet):
    serializer_class = DepartmentEmployeeSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        department_id = self.kwargs['department_id']
        return DepartmentEmployee.objects.filter(department_id=department_id)
