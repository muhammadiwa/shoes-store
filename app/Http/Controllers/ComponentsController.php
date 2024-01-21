<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ComponentsController extends Controller
{

    /**
     * Typography Basic
     */
    public function typography()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Typography',
                'url' => '/components-typography',
                'active' => true
            ],

        ];
        return view('elements.components.typography', [
            'pageTitle' => 'Typography',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }



    /**
     * Color Basic
     */
    public function color()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Color',
                'url' => '/components-colors',
                'active' => true
            ],

        ];
        return view('elements.components.colors', [
            'pageTitle' => 'Color',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }



    /**
     * Alert view
     */
    public function alert()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Alert',
                'url' => '/components-alert',
                'active' => true
            ],

        ];
        return view('elements.components.alert', [
            'pageTitle' => 'Alert',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * Button view
     */
    public function button()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Button',
                'url' => '/components-button',
                'active' => true
            ],

        ];
        return view('elements.components.button', [
            'pageTitle' => 'Button',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * Card view
     */
    public function card()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Card',
                'url' => '/components-card',
                'active' => true
            ],

        ];
        return view('elements.components.card', [
            'pageTitle' => 'Card',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * carousel view
     */
    public function carousel()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Carousel',
                'url' => '/components-carousel',
                'active' => true
            ],

        ];
        return view('elements.components.carousel', [
            'pageTitle' => 'Carousel',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * dropdown view
     */
    public function dropdown()
    {
        $breadcrumbsItems = [
            [
                'name' => 'dropdown',
                'url' => '/components-dropdown',
                'active' => true
            ],

        ];
        return view('elements.components.dropdown', [
            'pageTitle' => 'Dropdown',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * image view
     */
    public function image()
    {
        $breadcrumbsItems = [
            [
                'name' => 'image',
                'url' => '/components-image',
                'active' => true
            ],

        ];
        return view('elements.components.image', [
            'pageTitle' => 'Image',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * modal view
     */
    public function modal()
    {
        $breadcrumbsItems = [
            [
                'name' => 'modal',
                'url' => '/components-modal',
                'active' => true
            ],

        ];
        return view('elements.components.modal', [
            'pageTitle' => 'Modal',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * progressBar view
     */
    public function progressBar()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Progress Bar',
                'url' => '/components-progress-bar',
                'active' => true
            ],
        ];
        return view('elements.components.progress-bar', [
            'pageTitle' => 'Progress Bar',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * placeholder view
     */
    public function placeholder()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Placeholder',
                'url' => '/components-placeholder',
                'active' => true
            ],
        ];
        return view('elements.components.placeholder', [
            'pageTitle' => 'Placeholder',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * Tab view
     */
    public function tab()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Tab',
                'url' => '/components-tab',
                'active' => true
            ],
        ];
        return view('elements.components.tab', [
            'pageTitle' => 'Tab & Accordion',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * Badge view
     */
    public function badges()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Badges',
                'url' => '/components-badges',
                'active' => true
            ],
        ];
        return view('elements.components.badges', [
            'pageTitle' => 'Badges',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * pagination  view
     */
    public function pagination()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Pagination',
                'url' => '/components-pagination',
                'active' => true
            ],
        ];
        return view('elements.components.pagination', [
            'pageTitle' => 'Pagination',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * video view
     */
    public function video()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Video',
                'url' => '/components-video',
                'active' => true
            ],
        ];
        return view('elements.components.video', [
            'pageTitle' => 'Video',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * tooltip view
     */
    public function tooltip()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Tooltip',
                'url' => '/components-tooltip',
                'active' => true
            ],
        ];
        return view('elements.components.tooltip', [
            'pageTitle' => 'Tooltip & Popover',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }
}
