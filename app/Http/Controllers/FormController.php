<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class FormController extends Controller
{

    /**
     * input view
     */
    public function input()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input',
                'url' => '/forms-input',
                'active' => true
            ],
        ];
        return view('elements.forms.input', [
            'pageTitle' => 'Form input',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }



    /**
     * group view
     */
    public function group()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input Group',
                'url' => '/forms-input-group',
                'active' => true
            ],
        ];
        return view('elements.forms.input-group', [
            'pageTitle' => 'Input Group',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }


    /**
     * layout view
     */
    public function layout()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input layout',
                'url' => '/forms-input-layout',
                'active' => true
            ],
        ];
        return view('elements.forms.input-layout', [
            'pageTitle' => 'Input layout',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * validation view
     */
    public function validation()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input validation',
                'url' => '/forms.input-validation',
                'active' => true
            ],
        ];
        return view('elements.forms.form-validation', [
            'pageTitle' => 'Input validation',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }


    /**
     * wizard view
     */
    public function wizard()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input wizard',
                'url' => '/forms.input-wizard',
                'active' => true
            ],
        ];
        return view('elements.forms.wizard', [
            'pageTitle' => 'Input wizard',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }


    /**
     * input Mask view
     */
    public function inputMask()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input Mask',
                'url' => '/forms.input-mask',
                'active' => true
            ],
        ];
        return view('elements.forms.input-mask', [
            'pageTitle' => 'Input Mask',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * file Input view
     */
    public function fileInput()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input File',
                'url' => '/forms.input-file',
                'active' => true
            ],
        ];
        return view('elements.forms.file-input', [
            'pageTitle' => 'Input File',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * form repeater view
     */
    public function repeater()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input File',
                'url' => '/forms.input-file',
                'active' => true
            ],
        ];
        return view('elements.forms.form-repeater', [
            'pageTitle' => 'Input File',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * form textarea view
     */
    public function textarea()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input textarea',
                'url' => '/forms.input-textarea',
                'active' => true
            ],
        ];
        return view('elements.forms.textarea', [
            'pageTitle' => 'Input Textarea',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * form checkbox view
     */
    public function checkbox()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input checkbox',
                'url' => '/forms.input-checkbox',
                'active' => true
            ],
        ];
        return view('elements.forms.checkbox', [
            'pageTitle' => 'Input Checkbox',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * form radio view
     */
    public function radio()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input radio',
                'url' => '/forms.input-radio',
                'active' => true
            ],
        ];
        return view('elements.forms.radio', [
            'pageTitle' => 'Input Radio',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * form switch view
     */
    public function switch()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input switch',
                'url' => '/forms-switch',
                'active' => true
            ],
        ];
        return view('elements.forms.switch', [
            'pageTitle' => 'Input Switch',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * form select view
     */
    public function select()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Input select',
                'url' => '/forms-select',
                'active' => true
            ],
        ];
        return view('elements.forms.select', [
            'pageTitle' => 'Input Select',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

    /**
     * form date time picker  view
     */
    public function dateTimePicker()
    {
        $breadcrumbsItems = [
            [
                'name' => 'Date time picker',
                'url' => '/forms-date-time-picker',
                'active' => true
            ],
        ];
        return view('elements.forms.date-time-picker', [
            'pageTitle' => 'Date time picker',
            'breadcrumbItems' => $breadcrumbsItems,
        ]);
    }

}
