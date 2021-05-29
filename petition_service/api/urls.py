from django.urls import path
from . import views

urlpatterns = [
    path('categories/', views.CategoryListView.as_view()),
    path('petitions/', views.PetitionListView.as_view()),
    path('petitions', views.PetitionListView.as_view()),
    path('petitions/<int:pk>/', views.PetitionDetailView.as_view()),
    path('petitions/<int:pk>/voters', views.VotedUsersView.as_view()),
    path('petitions/save/', views.PetitionCreateView.as_view()),
    path('petitions/vote/<int:pk>/', views.VoteSubmitView.as_view()),
    path('users/', views.UserListView.as_view()),
    path('statistics/', views.StatisticsView.as_view()),
    path('logout/', views.LogoutView.as_view()),
]