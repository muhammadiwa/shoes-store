<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid xl:grid-cols-2 grid-cols-1 gap-6">
            <!-- BEGIN: Basic Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Basic</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-primary">primary</button>
                            <button class="btn inline-flex justify-center btn-secondary">secondary</button>
                            <button class="btn inline-flex justify-center btn-info">info</button>
                            <button class="btn inline-flex justify-center btn-success">success</button>
                            <button class="btn inline-flex justify-center btn-warning">warning</button>
                            <button class="btn inline-flex justify-center btn-danger">danger</button>
                            <button class="btn inline-flex justify-center btn-dark">dark</button>
                            <button class="btn inline-flex justify-center btn-light">light</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Basic Buttons -->
            <!-- BEGIN: Outline Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Outline</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-outline-primary">primary</button>
                            <button class="btn inline-flex justify-center btn-outline-secondary">secondary</button>
                            <button class="btn inline-flex justify-center btn-outline-info">info</button>
                            <button class="btn inline-flex justify-center btn-outline-success">success</button>
                            <button class="btn inline-flex justify-center btn-outline-warning">warning</button>
                            <button class="btn inline-flex justify-center btn-outline-danger">danger</button>
                            <button class="btn inline-flex justify-center btn-outline-dark">dark</button>
                            <button class="btn inline-flex justify-center btn-outline-light">light</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Outline Buttons -->
            <!-- BEGIN: Light Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Light</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-primary light">primary</button>
                            <button class="btn inline-flex justify-center btn-secondary light">secondary</button>
                            <button class="btn inline-flex justify-center btn-info light">info</button>
                            <button class="btn inline-flex justify-center btn-success light">success</button>
                            <button class="btn inline-flex justify-center btn-warning light">warning</button>
                            <button class="btn inline-flex justify-center btn-danger light">danger</button>
                            <button class="btn inline-flex justify-center btn-dark light">dark</button>
                            <button class="btn inline-flex justify-center btn-light light">light</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Light Buttons -->
            <!-- BEGIN: Raised Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Raised</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-primary shadow-base2">primary</button>
                            <button class="btn inline-flex justify-center btn-secondary shadow-base2">secondary</button>
                            <button class="btn inline-flex justify-center btn-info shadow-base2">info</button>
                            <button class="btn inline-flex justify-center btn-success shadow-base2">success</button>
                            <button class="btn inline-flex justify-center btn-warning shadow-base2">warning</button>
                            <button class="btn inline-flex justify-center btn-danger shadow-base2">danger</button>
                            <button class="btn inline-flex justify-center btn-dark shadow-base2">dark</button>
                            <button class="btn inline-flex justify-center btn-light shadow-base2">light</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Raised Buttons -->
            <!-- BEGIN: Rounded Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Rounded</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-primary rounded-[25px]">primary</button>
                            <button class="btn inline-flex justify-center btn-secondary rounded-[25px]">secondary</button>
                            <button class="btn inline-flex justify-center btn-info rounded-[25px]">info</button>
                            <button class="btn inline-flex justify-center btn-success rounded-[25px]">success</button>
                            <button class="btn inline-flex justify-center btn-warning rounded-[25px]">warning</button>
                            <button class="btn inline-flex justify-center btn-danger rounded-[25px]">danger</button>
                            <button class="btn inline-flex justify-center btn-dark rounded-[25px]">dark</button>
                            <button class="btn inline-flex justify-center btn-light rounded-[25px]">light</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Rounded Buttons -->
            <!-- BEGIN: Rounded Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Rounded Outline</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-outline-primary rounded-[25px]">primary</button>
                            <button class="btn inline-flex justify-center btn-outline-secondary rounded-[25px]">secondary</button>
                            <button class="btn inline-flex justify-center btn-outline-info rounded-[25px]">info</button>
                            <button class="btn inline-flex justify-center btn-outline-success rounded-[25px]">success</button>
                            <button class="btn inline-flex justify-center btn-outline-warning rounded-[25px]">warning</button>
                            <button class="btn inline-flex justify-center btn-outline-danger rounded-[25px]">danger</button>
                            <button class="btn inline-flex justify-center btn-outline-dark rounded-[25px]">dark</button>
                            <button class="btn inline-flex justify-center btn-outline-light rounded-[25px]">light</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Rounded Buttons -->
            <!-- BEGIN: Icon Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Icon</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-primary "> <span class="flex items-center">
                    <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="heroicons-outline:newspaper"></iconify-icon>
                    <span>Left Icon</span> </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-outline-primary "> <span class="flex items-center">
                    <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="heroicons-outline:newspaper"></iconify-icon>
                    <span>Left Icon</span> </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-primary "> <span class="flex items-center">
                    <span>Right Icon</span>
                                <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:newspaper"></iconify-icon>
                                </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-outline-primary "> <span class="flex items-center">
                    <span>Right Icon</span>
                                <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:newspaper"></iconify-icon>
                                </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-primary "> <span class="flex items-center">
                    <iconify-icon class="text-xl" icon="heroicons-outline:newspaper"></iconify-icon>
                  </span> </button>
                            <button class="btn inline-flex justify-center btn-outline-primary "> <span class="flex items-center">
                    <iconify-icon class="text-xl" icon="heroicons-outline:newspaper"></iconify-icon>
                  </span> </button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Icon Buttons -->
            <!-- BEGIN: Icon Rounded Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Icon Rounded</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-primary rounded-[25px]"> <span class="flex items-center">
                    <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="heroicons-outline:newspaper"></iconify-icon>
                    <span>Left Icon</span> </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-outline-primary rounded-[25px]"> <span class="flex items-center">
                    <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="heroicons-outline:newspaper"></iconify-icon>
                    <span>Left Icon</span> </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-primary rounded-[25px]"> <span class="flex items-center">
                    <span>Right Icon</span>
                                <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:newspaper"></iconify-icon>
                                </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-outline-primary rounded-[25px]"> <span class="flex items-center">
                    <span>Right Icon</span>
                                <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:newspaper"></iconify-icon>
                                </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-primary rounded-[25px]"> <span class="flex items-center">
                    <iconify-icon class="text-xl" icon="heroicons-outline:newspaper"></iconify-icon>
                  </span> </button>
                            <button class="btn inline-flex justify-center btn-outline-primary rounded-[25px]"> <span class="flex items-center">
                    <iconify-icon class="text-xl" icon="heroicons-outline:newspaper"></iconify-icon>
                  </span> </button>
                            <button class="btn inline-flex h-12 w-12 items-center justify-center btn-primary rounded-full"> <span class="flex items-center">
                    <iconify-icon class="text-xl" icon="heroicons-outline:newspaper"></iconify-icon>
                  </span> </button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Icon Rounded Buttons -->
            <!-- BEGIN: Size Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Size</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-primary btn-xl"> <span class="flex items-center">
                    <span>Large</span> </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-primary"> <span class="flex items-center">
                    <span>Deault</span> </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-primary btn-sm"> <span class="flex items-center">
                    <span>Small</span> </span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Size Buttons -->
            <!-- BEGIN: Disabled Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Disabled</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-primary cursor-not-allowed light" disabled="disabled">primary</button>
                            <button class="btn inline-flex justify-center btn-secondary cursor-not-allowed light" disabled="disabled">secondary</button>
                            <button class="btn inline-flex justify-center btn-info cursor-not-allowed light" disabled="disabled">info</button>
                            <button class="btn inline-flex justify-center btn-success cursor-not-allowed light" disabled="disabled">success</button>
                            <button class="btn inline-flex justify-center btn-warning cursor-not-allowed light" disabled="disabled">warning</button>
                            <button class="btn inline-flex justify-center btn-danger cursor-not-allowed light" disabled="disabled">danger</button>
                            <button class="btn inline-flex justify-center btn-dark cursor-not-allowed light" disabled="disabled">dark</button>
                            <button class="btn inline-flex justify-center btn-light cursor-not-allowed light" disabled="disabled">light</button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Disabled Buttons -->
            <!-- BEGIN: Loading Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Loading</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-primary ">
                                <iconify-icon class="text-xl spin-slow ltr:mr-2 rtl:ml-2 relative top-[1px]" icon="line-md:loading-twotone-loop"></iconify-icon> <span>Loading</span> </button>
                            <button class="btn inline-flex justify-center btn-secondary ">
                                <iconify-icon class="text-xl spin-slow ltr:mr-2 rtl:ml-2 relative top-[1px]" icon="line-md:loading-twotone-loop"></iconify-icon> <span>Loading</span> </button>
                            <button class="btn inline-flex justify-center btn-info ">
                                <iconify-icon class="text-xl spin-slow ltr:mr-2 rtl:ml-2 relative top-[1px]" icon="line-md:loading-twotone-loop"></iconify-icon> <span>Loading</span> </button>
                            <button class="btn inline-flex justify-center btn-success ">
                                <iconify-icon class="text-xl spin-slow ltr:mr-2 rtl:ml-2 relative top-[1px]" icon="line-md:loading-twotone-loop"></iconify-icon> <span>Loading</span> </button>
                            <button class="btn inline-flex justify-center btn-warning ">
                                <iconify-icon class="text-xl spin-slow ltr:mr-2 rtl:ml-2 relative top-[1px]" icon="line-md:loading-twotone-loop"></iconify-icon> <span>Loading</span> </button>
                            <button class="btn inline-flex justify-center btn-danger ">
                                <iconify-icon class="text-xl spin-slow ltr:mr-2 rtl:ml-2 relative top-[1px]" icon="line-md:loading-twotone-loop"></iconify-icon> <span>Loading</span> </button>
                            <button class="btn inline-flex justify-center btn-dark ">
                                <iconify-icon class="text-xl spin-slow ltr:mr-2 rtl:ml-2 relative top-[1px]" icon="line-md:loading-twotone-loop"></iconify-icon> <span>Loading</span> </button>
                            <button class="btn inline-flex justify-center btn-light ">
                                <iconify-icon class="text-xl spin-slow ltr:mr-2 rtl:ml-2 relative top-[1px]" icon="line-md:loading-twotone-loop"></iconify-icon> <span>Loading</span> </button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Loading Buttons -->
            <!-- BEGIN: Group Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Group Buttons</div>
                        </div>
                    </header>
                    <div class="card-text h-full space-y-5">
                        <div class="outline-buttons">
                            <div class="groupButtons">
                                <button class="btn inline-flex justify-center btn-outline-primary active"> Weekly </button>
                                <button class="btn inline-flex justify-center btn-outline-primary "> Monthly </button>
                                <button class="btn inline-flex justify-center btn-outline-primary "> Yearly </button>
                            </div>
                        </div>
                        <div class="normal-buttons">
                            <div class="groupButtons">
                                <button class="btn inline-flex justify-center btn-primary"> Weekly </button>
                                <button class="btn inline-flex justify-center btn-primary active"> Monthly </button>
                                <button class="btn inline-flex justify-center btn-primary "> Yearly </button>
                            </div>
                        </div>
                        <div class="normal-buttons">
                            <div class="groupButtons">
                                <button class="btn inline-flex justify-center btn-secondary"> Weekly </button>
                                <button class="btn inline-flex justify-center btn-secondary active"> Monthly </button>
                                <button class="btn inline-flex justify-center btn-secondary "> Yearly </button>
                            </div>
                        </div>
                        <div class="normal-buttons">
                            <div class="groupButtons">
                                <button class="btn inline-flex justify-center btn-primary active"> <span class="flex items-center">
                      <iconify-icon class="text-2xl relative top-[1px]" icon="ic:round-keyboard-arrow-left"></iconify-icon>
                      <span>Back</span> </span>
                                </button>
                                <button class="btn inline-flex justify-center btn-primary "> <span class="flex items-center">
                      <span>Next</span>
                                    <iconify-icon class="text-2xl relative top-[1px]" icon="ic:round-keyboard-arrow-right"></iconify-icon>
                                    </span>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Group Buttons -->
            <!-- BEGIN: Block Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Block</div>
                        </div>
                    </header>
                    <div class="card-text h-full ">
                        <div class="btn-group-example btn-group">
                            <button class="btn inline-flex justify-center btn-primary block-btn"> <span class="flex items-center">
                    <span>Primary</span> </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-secondary block-btn"> <span class="flex items-center">
                    <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="heroicons-outline:newspaper"></iconify-icon>
                    <span>Left Icon</span> </span>
                            </button>
                            <button class="btn inline-flex justify-center btn-success block-btn"> <span class="flex items-center">
                    <span>Right Icon</span>
                                <iconify-icon class="text-xl ltr:ml-2 rtl:mr-2" icon="heroicons-outline:newspaper"></iconify-icon>
                                </span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Block Buttons -->
            <!-- BEGIN: Linked Buttons -->
            <div class="card">
                <div class="card-body flex flex-col p-6 active">
                    <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                        <div class="flex-1">
                            <div class="card-title text-slate-900 dark:text-white">Linked Button</div>
                        </div>
                    </header>
                    <div class="card-text h-full menu-open">
                        <div class="btn-group-example btn-group"> <a href="buttons.html" class="btn inline-flex justify-center mx-2 mt-3 btn-primary active">primary</a> <a href="buttons.html" class="btn inline-flex justify-center mx-2 mt-3 btn-secondary active">secondary</a> <a href="buttons.html" class="btn inline-flex justify-center mx-2 mt-3 btn-info active">info</a> <a href="buttons.html" class="btn inline-flex justify-center mx-2 mt-3 btn-success active">success</a> <a href="buttons.html" class="btn inline-flex justify-center mx-2 mt-3 btn-warning active">warning</a> <a href="buttons.html" class="btn inline-flex justify-center mx-2 mt-3 btn-danger active">danger</a> <a href="buttons.html" class="btn inline-flex justify-center mx-2 mt-3 btn-dark active">dark</a> <a href="buttons.html" class="btn inline-flex justify-center mx-2 mt-3 btn-light active">light</a> </div>
                    </div>
                </div>
            </div>
            <!-- END: Linked Buttons -->
        </div>
    </div>
</x-app-layout>
