<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AppsController extends Controller
{
    /**
     * Display a chat view
     */
    public function chat()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Chat',
                'url' => '/chat',
                'active' => true
            ],

        ];
        return view('apps.chat', [
            'pageTitle' => 'Chat',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }


    /**
     * Display a email view
     */
    public function email()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Email',
                'url' => '/email',
                'active' => true
            ],

        ];
        return view('apps.email', [
            'pageTitle' => 'Email',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * Display a kanban view
     */
    public function kanban()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Kanban',
                'url' => '/kanban',
                'active' => true
            ],
        ];
        return view('apps.kanban', [
            'pageTitle' => 'Kanban ',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }


    /**
     * Display a Calender view
     */
    public function calender()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Calender',
                'url' => '/calender',
                'active' => true
            ],
        ];
        return view('apps.calender', [
            'pageTitle' => 'Calender ',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }


    /**
     * Display a todo view
     */
    public function todo()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Todo',
                'url' => '/todo',
                'active' => true
            ],
        ];
        return view('apps.todo', [
            'pageTitle' => 'Todo ',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * Display a projects view
     */
    public function projects()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Projects',
                'url' => '/projects',
                'active' => true
            ],
        ];
        return view('apps.projects', [
            'pageTitle' => 'Projects ',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * Display a project details view
     */
    public function projectDetails()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Project Details',
                'url' => '/project-details',
                'active' => true
            ],
        ];
        return view('apps.project-details', [
            'pageTitle' => 'Project Details ',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }
}
