<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid grid-cols-2 gap-6">
            <div class="card">
              <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                  <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Default Tabs</div>
                  </div>
                </header>
                <div class="card-text h-full ">
                  <div>
                    <ul class="nav nav-tabs flex flex-col md:flex-row flex-wrap list-none border-b-0 pl-0 mb-4" id="tabs-tab" role="tablist">
                      <li class="nav-item" role="presentation">
                        <a href="#tabs-home" class="nav-link w-full block font-medium text-sm font-Inter leading-tight capitalize border-x-0 border-t-0 border-b border-transparent px-4 pb-2 my-2 hover:border-transparent focus:border-transparent active dark:text-slate-300" id="tabs-home-tab" data-bs-toggle="pill" data-bs-target="#tabs-home" role="tab" aria-controls="tabs-home" aria-selected="true">Home</a>
                      </li>
                      <li class="nav-item" role="presentation">
                        <a href="#tabs-profile" class="nav-link w-full block font-medium text-sm font-Inter leading-tight capitalize border-x-0 border-t-0 border-b border-transparent px-4 pb-2 my-2 hover:border-transparent focus:border-transparent dark:text-slate-300" id="tabs-profile-tab" data-bs-toggle="pill" data-bs-target="#tabs-profile" role="tab" aria-controls="tabs-profile" aria-selected="false">Profile</a>
                      </li>
                      <li class="nav-item" role="presentation">
                        <a href="#tabs-messages" class="nav-link w-full block font-medium text-sm font-Inter leading-tight capitalize border-x-0 border-t-0 border-b border-transparent px-4 pb-2 my-2 hover:border-transparent focus:border-transparent dark:text-slate-300" id="tabs-messages-tab" data-bs-toggle="pill" data-bs-target="#tabs-messages" role="tab" aria-controls="tabs-messages" aria-selected="false">Messages</a>
                      </li>
                      <li class="nav-item" role="presentation">
                        <a href="#tabs-settings" class="nav-link w-full block font-medium text-sm font-Inter leading-tight capitalize border-x-0 border-t-0 border-b border-transparent px-4 pb-2 my-2 hover:border-transparent focus:border-transparent dark:text-slate-300" id="tabs-settings-tab" data-bs-toggle="pill" data-bs-target="#tabs-settings" role="tab" aria-controls="tabs-settings" aria-selected="false">settings</a>
                      </li>
                    </ul>
                    <div class="tab-content" id="tabs-tabContent">
                      <div class="tab-pane fade show active" id="tabs-home" role="tabpanel" aria-labelledby="tabs-home-tab">
                        <p class="text-sm text-gray-500 dark:text-gray-200">
                          This is some placeholder content the
                          <strong>Home</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="tabs-profile" role="tabpanel" aria-labelledby="tabs-profile-tab">
                        <p class="text-sm text-gray-500 dark:text-gray-200">
                          This is some placeholder content the
                          <strong>Profile</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="tabs-messages" role="tabpanel" aria-labelledby="tabs-messages-tab">
                        <p class="text-sm text-gray-500 dark:text-gray-200">
                          This is some placeholder content the
                          <strong>Messages</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="tabs-settings" role="tabpanel" aria-labelledby="tabs-settings-tab">
                        <p class="text-sm text-gray-500 dark:text-gray-200">
                          This is some placeholder content the
                          <strong>Settings</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="card">
              <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                  <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Tabs With Icon</div>
                  </div>
                </header>
                <div class="card-text h-full">
                  <div>
                    <ul class="nav nav-tabs flex flex-col md:flex-row flex-wrap list-none border-b-0 pl-0 mb-4" id="tabs-tab" role="tablist">
                      <li class="nav-item" role="presentation">
                        <a href="#tabs-home-withIcon" class="nav-link w-full flex items-center font-medium text-sm font-Inter leading-tight capitalize border-x-0 border-t-0 border-b border-transparent px-4 pb-2 my-2 hover:border-transparent focus:border-transparent active dark:text-slate-300" id="tabs-home-withIcon-tab" data-bs-toggle="pill" data-bs-target="#tabs-home-withIcon" role="tab" aria-controls="tabs-home-withIcon" aria-selected="true">
                          <iconify-icon class="mr-1" icon="heroicons-outline:home"></iconify-icon>
                          Home</a>
                      </li>
                      <li class="nav-item" role="presentation">
                        <a href="#tabs-profile-withIcon" class="nav-link w-full flex items-center font-medium text-sm font-Inter leading-tight capitalize border-x-0 border-t-0 border-b border-transparent px-4 pb-2 my-2 hover:border-transparent focus:border-transparent dark:text-slate-300" id="tabs-profile-withIcon-tab" data-bs-toggle="pill" data-bs-target="#tabs-profile-withIcon" role="tab" aria-controls="tabs-profile-withIcon" aria-selected="false">
                          <iconify-icon class="mr-1" icon="heroicons-outline:user"></iconify-icon>
                          Profile</a>
                      </li>
                      <li class="nav-item" role="presentation">
                        <a href="#tabs-messages-withIcon" class="nav-link w-full flex items-center font-medium text-sm font-Inter leading-tight capitalize border-x-0 border-t-0 border-b border-transparent px-4 pb-2 my-2 hover:border-transparent focus:border-transparent dark:text-slate-300" id="tabs-messages-withIcon-tab" data-bs-toggle="pill" data-bs-target="#tabs-messages-withIcon" role="tab" aria-controls="tabs-messages-withIcon" aria-selected="false">
                          <iconify-icon class="mr-1" icon="heroicons-outline:chat-alt-2"></iconify-icon>
                          Messages</a>
                      </li>
                      <li class="nav-item" role="presentation">
                        <a href="#tabs-settings-withIcon" class="nav-link w-full flex items-center font-medium text-sm font-Inter leading-tight capitalize border-x-0 border-t-0 border-b border-transparent px-4 pb-2 my-2 hover:border-transparent focus:border-transparent dark:text-slate-300" id="tabs-settings-withIcon-tab" data-bs-toggle="pill" data-bs-target="#tabs-settings-withIcon" role="tab" aria-controls="tabs-settings-withIcon" aria-selected="false">
                          <iconify-icon class="mr-1" icon="clarity:settings-line"></iconify-icon>
                          Settings</a>
                      </li>
                    </ul>
                    <div class="tab-content" id="tabs-tabContent">
                      <div class="tab-pane fade show active" id="tabs-home-withIcon" role="tabpanel" aria-labelledby="tabs-home-withIcon-tab">
                        <p class="text-sm text-gray-500 dark:text-gray-200">
                          This is some placeholder content the
                          <strong>Home</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="tabs-profile-withIcon" role="tabpanel" aria-labelledby="tabs-profile-withIcon-tab">
                        <p class="text-sm text-gray-500 dark:text-gray-200">
                          This is some placeholder content the
                          <strong>Profile</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="tabs-messages-withIcon" role="tabpanel" aria-labelledby="tabs-messages-withIcon-tab">
                        <p class="text-sm text-gray-500 dark:text-gray-200">
                          This is some placeholder content the
                          <strong>Messages</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="tabs-settings-withIcon" role="tabpanel" aria-labelledby="tabs-settings-withIcon-tab">
                        <p class="text-sm text-gray-500 dark:text-gray-200">
                          This is some placeholder content the
                          <strong>Settings</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="card">
              <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                  <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Vertical Nav Tabs</div>
                  </div>
                </header>
                <div class="card-text h-full">
                  <div class="flex items-start">
                    <ul class="nav nav-pills flex flex-col flex-wrap list-none pl-0 mr-4" id="pills-tabVertical" role="tablist">
                      <li class="nav-item text-center mb-2" role="presentation">
                        <a href="#pills-homeVertical" class="nav-link block font-medium font-Inter text-sm leading-tight capitalize rounded-md px-6 py-3 focus:outline-none focus:ring-0 dark:bg-slate-900 dark:text-slate-300 active" id="pills-home-tabVertical" data-bs-toggle="pill" data-bs-target="#pills-homeVertical" role="tab" aria-controls="pills-homeVertical" aria-selected="true">Home</a>
                      </li>
                      <li class="nav-item flex-grow text-center my-2" role="presentation">
                        <a href="#pills-profileVertical" class="nav-link block font-medium font-Inter text-sm leading-tight capitalize rounded-md px-6 py-3 focus:outline-none focus:ring-0 dark:bg-slate-900 dark:text-slate-300" id="pills-profile-tabVertical" data-bs-toggle="pill" data-bs-target="#pills-profileVertical" role="tab" aria-controls="pills-profileVertical" aria-selected="false">Profile</a>
                      </li>
                      <li class="nav-item flex-grow text-center my-2" role="presentation">
                        <a href="#pills-contactVertical" class="nav-link block font-medium font-Inter text-sm leading-tight capitalize rounded-md px-6 py-3 focus:outline-none focus:ring-0 dark:bg-slate-900 dark:text-slate-300" id="pills-contact-tabVertical" data-bs-toggle="pill" data-bs-target="#pills-contactVertical" role="tab" aria-controls="pills-contactVertical" aria-selected="false">Messages</a>
                      </li>
                      <li class="nav-item flex-grow text-center my-2" role="presentation">
                        <a href="#pills-settingsVertical" class="nav-link block font-medium font-Inter text-sm leading-tight capitalize rounded-md px-6 py-3 focus:outline-none focus:ring-0 dark:bg-slate-900 dark:text-slate-300 " id="pills-settings-tabVertical" data-bs-toggle="pill" data-bs-target="#pills-settingsVertical" role="tab" aria-controls="pills-settingsVertical" aria-selected="false">Settings</a>
                      </li>
                    </ul>
                    <div class="tab-content" id="pills-tabContentVertical">
                      <div class="tab-pane fade show active" id="pills-homeVertical" role="tabpanel" aria-labelledby="pills-home-tabVertical">
                        This is some placeholder content the
                          <strong>Home</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="pills-profileVertical" role="tabpanel" aria-labelledby="pills-profile-tabVertical">
                        This is some placeholder content the
                          <strong>Profile</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="pills-contactVertical" role="tabpanel" aria-labelledby="pills-contact-tabVertical">
                        This is some placeholder content the
                          <strong>Contact</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="pills-settingsVertical" role="tabpanel" aria-labelledby="pills-settings-tabVertical">
                        This is some placeholder content the
                          <strong>Settings</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="card">
              <div class="card-body flex flex-col p-6">
                <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
                  <div class="flex-1">
                    <div class="card-title text-slate-900 dark:text-white">Horizontal Nav Tabs</div>
                  </div>
                </header>
                <div class="card-text h-full">
                  <div>
                    <ul class="nav nav-pills flex items-center flex-wrap list-none pl-0 mb-6 space-x-4 " id="pills-tabHorizontal" role="tablist">
                      <li class="nav-item text-center" role="presentation">
                        <a href="#pills-homeHorizontal" class="nav-link block font-medium font-Inter text-sm leading-tight capitalize rounded-md px-6 py-3 focus:outline-none focus:ring-0 active dark:bg-slate-900 dark:text-slate-300" id="pills-home-tabHorizontal" data-bs-toggle="pill" data-bs-target="#pills-homeHorizontal" role="tab" aria-controls="pills-homeHorizontal" aria-selected="true">Home</a>
                      </li>
                      <li class="nav-item text-center" role="presentation">
                        <a href="#pills-profileHorizontal" class="nav-link block font-medium font-Inter text-sm leading-tight capitalize rounded-md px-6 py-3 focus:outline-none focus:ring-0 dark:bg-slate-900 dark:text-slate-300" id="pills-profile-tabHorizontal" data-bs-toggle="pill" data-bs-target="#pills-profileHorizontal" role="tab" aria-controls="pills-profileHorizontal" aria-selected="false">Profile</a>
                      </li>
                      <li class="nav-item text-center" role="presentation">
                        <a href="#pills-contactHorizontal" class="nav-link block font-medium font-Inter text-sm leading-tight capitalize rounded-md px-6 py-3 focus:outline-none focus:ring-0 dark:bg-slate-900 dark:text-slate-300 " id="pills-contact-tabHorizontal" data-bs-toggle="pill" data-bs-target="#pills-contactHorizontal" role="tab" aria-controls="pills-contactHorizontal" aria-selected="false">Messages</a>
                      </li>
                      <li class="nav-item text-center" role="presentation">
                        <a href="#pills-settingsHorizontal" class="nav-link block font-medium font-Inter text-sm leading-tight capitalize rounded-md px-6 py-3 focus:outline-none focus:ring-0 dark:bg-slate-900 dark:text-slate-300 " id="pills-settings-tabHorizontal" data-bs-toggle="pill" data-bs-target="#pills-settingsHorizontal" role="tab" aria-controls="pills-settingsHorizontal" aria-selected="false">Settings</a>
                      </li>
                    </ul>
                    <div class="tab-content" id="pills-tabContentHorizontal">
                      <div class="tab-pane fade show active" id="pills-homeHorizontal" role="tabpanel" aria-labelledby="pills-home-tabHorizontal">
                        This is some placeholder content the
                          <strong>Home</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="pills-profileHorizontal" role="tabpanel" aria-labelledby="pills-profile-tabHorizontal">
                        This is some placeholder content the
                          <strong>Profile</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="pills-contactHorizontal" role="tabpanel" aria-labelledby="pills-contact-tabHorizontal">
                        This is some placeholder content the
                          <strong>Contact</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                      <div class="tab-pane fade" id="pills-settingsHorizontal" role="tabpanel" aria-labelledby="pills-settings-tabHorizontal">
                        This is some placeholder content the
                          <strong>Settings</strong>
                          tab's associated content. Clicking another tab will toggle the visibility of this one for the next. The tab JavaScript swaps classes to control the content visibility and styling. consectetur adipisicing elit. Ab ipsa!</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
        </div>
    </div>
</x-app-layout>
