#################################################
OpenRPD Software Development Guidelines and Roles
#################################################

Project Participants
====================

Project Participants are organizations that sign the OpenRPD Participation
Agreement. Project Participants must sign the agreement before they are given
access to the OpenRPD project source code.

Project Working Group / Project Members
=======================================

Working Groups are comprised of representatives from participating
organizations. These representatives constitute the Project Members. Membership
is by individual within a participating business entity. Project Members have
read and write access to most project assets.


C3: OpenRPD Development Process
===============================

All C3 projects are driven forward by a development process. The OpenRPD
development process is designed to support a code base where we expect a
significant number of contributions from community participants. Roles are
defined for participants in the process to help manage those contributions
effectively.

Project Roles
=============

The OpenRPD project includes the following roles and responsibilities:

+-------------------+-------------------------------------+--------------------+
|Role               |Responsibilities                     |Who?                |
+===================+=====================================+====================+
|Project Chair      |The Project chair is responsible for:|Co-chairs -- Karthik|
|                   |                                     |Sundaresan and John |
|                   |* Identifying new Working Groups     |Chapman             |
|                   |* Appointing Working Group Chairs    |                    |
|                   |* Track Working Group progress –     |                    |
|                   |  ensure project goals are met       |                    |
|                   |* Appointing Committers              |                    |
+-------------------+-------------------------------------+--------------------+
|Working Group Chair|The Working Group Chair:             |Co-chairs -- Karthik|
|                   |                                     |Sundaresan and John |
|                   |* Assists the working group with     |Chapman             |
|                   |  identification and prioritization  |                    |
|                   |  of work items                      |                    |
|                   |* Tracks work item progress          |                    |
|                   |* Setting and communicating source   |                    |
|                   |  code maintenance and administration|                    |
|                   |  policies                           |                    |
+-------------------+-------------------------------------+--------------------+
|Project Members    |Individuals with read and write      |Open RPD Participant|
|                   |access to the project assets. Members|representatives /   |
|                   |may serve in Committer or Developer  |working group       |
|                   |roles. They are responsible for:     |members.            |
|                   |                                     |                    |
|                   |* Developing software for the project|                    |
|                   |* Ensuring the consistency of the    |                    |
|                   |  project work and conformance to the|                    |
|                   |  overall project goals              |                    |
|                   |* Receiving and reviewing proposals  |                    |
|                   |  for updates to the code            |                    |
|                   |* Developing and maintaining         |                    |
|                   |  documentation and other project    |                    |
|                   |  assets                             |                    |
+-------------------+-------------------------------------+--------------------+
|Committers         |Committers are Project Members with  |Karthik Sundaresan  |
|                   |additional responsibilities to:      |(CL), John Chapman  |
|                   |                                     |(Cisco), Anlu Yan   |
|                   |* Approve candidate code submissions |(Cisco), Huaidong   |
|                   |  for merge into the project main    |Lou (Cisco), Phil   |
|                   |  branch                             |Rosenberg-Watt (CL),|
|                   |* Assume ownership of project        |Carey Sonsino (CL), |
|                   |  infrastructure                     |Kevin Kershaw (CL)  |
|                   |* Assist project chairs in the       |                    |
|                   |  selection of additional committers |                    |
|                   |  based on merit                     |                    |
+-------------------+-------------------------------------+--------------------+
|Developers         |Developers are Project Members who:  |Open RPD Participant|
|                   |                                     |representatives /   |
|                   |* Develop and submit new code as     |working group       |
|                   |  merge candidates for review and    |members             |
|                   |  approval by committers             |                    |
|                   |* Review other developers' code in   |                    |
|                   |  their area(s) of expertise         |                    |
+-------------------+-------------------------------------+--------------------+


Project Wiki
============

Each project in the C3 Community hosts a wiki containing information about the
various project tools and assets. The OpenRPD project wiki has an overview page
(`OpenRPD Reference Software C3 Home`_) providing links to the other OpenRPD
assets (FAQs, SCM tools, bug tracker, etc.). The format for project web pages
can be flexible so long as the top level page for an individual project provides
links to all the elements that exist for that project. The wiki is hosted in the
CableLabs (Atlassian) Confluence system. Project committers and developers edit
wiki content to support the goals of the OpenRPD project.

.. _OpenRPD Reference Software C3 Home: https://community.cablelabs.com/wiki/display/C3/OpenRPD+Reference+Software+C3+Home


SCM tools
=========

In a multi-site, collaborative development like OpenRPD, the SCM tools play a
critical role. In order to keep the standards for contributed code high, the
OpenRPD projects uses a Git repository wrapped within a code review tool called
Gerrit. Combined with a set of well-known roles, Gerrit supports an organized
approach for change review and integration. CableLabs also recommends the use
of git-review_, a Git add-on that helps manage patch submission. More
information on best practices for using Gerrit (and Git_) can be found in the
section on `Contribution Process and SCM Tools`_. A link to the OpenRPD
projects in Gerrit is available on the OpenRPD Reference Software C3 Home page.

.. _git-review: https://www.mediawiki.org/wiki/Gerrit/git-review

.. _Git: https://git-scm.com/


Continuous Integration tools
============================

The `C3 Jenkins`_ software is integrated with Gerrit to manage triggered builds
of the project software. Each new change or change revision (known as a patch
set) that is uploaded to Gerrit will trigger Jenkins to automatically validate
the code before it is manually merged into the master branch. There are
separate :ref:`jenkins-jobs` to build the Remote PHY software and the Core
Emulator.

.. _C3 Jenkins: https://c3jenkins.cablelabs.com/


Bug Tracking
============

A `Jira project for OpenRPD <https://community.cablelabs.com/browse/C3RPHY/>`_
is available in the C3 environment to manage bugs, organize development tasks,
and log issues raised during the course of development.


Contribution Process and SCM Tools
==================================

.. ATTENTION::

   Writing commit log messages is important. Please see `this site
   <http://chris.beams.io/posts/git-commit/>`_ for an overview of how to
   properly structure a commit message.

Thanks to Linus Torvalds for a very powerful, if confusing, distributed
concurrent versioning system (DCVS) – **Git**. While Git distributes the SCM
workload, unfortunately it has a steep learning curve to it. We highly
recommend that every developer gain a thorough understanding of the
fundamentals of Git by reading the free, `online Pro Git book
<https://git-scm.com/book/en/v2>`_. While our interface to manage software
changes on OpenRPD is through Gerrit, it is still Git underneath. 

After the initial software contribution from Cisco was set up in the C3 Gerrit
System, the project "opened for business" to OpenRPD Project Participants.
Project Members may download the OpenRPD repositories to their local systems
and begin developing against them. As the project moves forward, developers
will create software changes that are candidates for merge back into the main
project trunk. Gerrit enforces a review process around acceptance of proposed
changes. 

At a top level, the steps involved in making a change are:

* Developer clones OpenRPD repository locally
* Developer modifies and tests changes in their local environment
* Developer pushes tested changes to Gerrit
* Gerrit notifies reviewers of the proposed change (developer can add reviewers
  to change if necessary)
* Gerrit triggers Jenkins job(s) to build and execute configured tests for the
  proposed changes
* Developers who are not "committers" will be able to vote on the change (+1, 0,
  or -1). View your voting options by selecting the "Reply" button on the Gerrit
  GUI.
* A successful run of the Jenkins job(s) provides **Verify** (+1) vote for the
  change
* Committer reviews the change, voting +2, +1, 0, -1, or -2.
* Any negative vote will reject the change; return to the developer for rework
* A +2 vote by at least one committer is required to move the change forward and
  allow merge to the project master branch.  If Committer votes +2 (and all
  other votes are +1), the Committer should merge the patch by selecting the
  "Merge" button on the Gerrit GUI.
* If changes to the patch are required, the path to "merge" becomes more
  complicated. We'll talk about that path shortly.

To help you acclimatize to the Gerrit change world, let's try to clarify a
little bit of how Gerrit works:

When you push a commit from your local repository up to Gerrit, Gerrit looks to
see if there is a Change-Id hash in the commit message. Gerrit uses the
Change-Id: to track which commits should create new patch sets on which
changes.  If Gerrit does not find the Change-Id hash in the commit message,
Gerrit will create a new Change-Id, add it to the commit message, and create a
*new* change.  Since this happens after you make the commit on your local
repository, your local repository does not have the Gerrit Change-Id in the
commit message. The whole thing will happen again when you make another push to
Gerrit, because Gerrit has no way of knowing you're adding on to a previous
change. You can find more explanation for this mechanism at `this link
<https://gerrit.cablelabs.com/Documentation/user-changeid.html>`_.

On the OpenRPD project, we use the git review tool to help manage this Gerrit
behavior. While the git-review plugin is not strictly required for using
Gerrit, it is recommended – *after* you have gained a thorough understanding of
how Git works.

.. WARNING::

  Previous SCM tools such as SVN do not translate directly to Git, and
  *attempting to retain an older conceptual model while working with Git will
  inevitably cause problems*.

Gerrit & Git Review
-------------------

Git-review is a command-line tool for Git / `Gerrit
<https://www.mediawiki.org/wiki/Gerrit>`_ that makes it easier to configure
your local Git repo, to submit a change, or to fetch and modify an existing
change. Git-review simplifies working with Gerrit repositories so you don't
have to remember some pretty confusing commands. To use git-review, you will
need to install the git-review package in your development environment. You can
find detailed instructions about installing, configuring, and using git-review
at `this URL <https://www.mediawiki.org/wiki/Gerrit/git-review>`_.

After you install git-review on your client system, you need to run ``git
review -s`` to configure git-review and the hooks for managing "Change-id"
correctly. 

Now, when you use git review to push your local commit(s) to the Gerrit server,
the git-review plugin will generate the Change-Id locally, append it to the
commit message, and *then* push the change to Gerrit.  When using the
git-review plug-in to help manage multiple iterations (patches) for a change,
use ``git review -d yy`` (where yy is the change number to download). This
combines several steps into one. It creates a new local branch named after the
change on your client, fetches the change set from Gerrit into the branch, and
switches your session into that branch. Then you can work on the local change
branch by making edits and commits locally, and when you're done, use ``git
commit --amend`` to push your patch to the change into your local repository as
a the appropriate branch in Gerrit.

That way, when you do a ``commit --amend`` locally and then do another ``git
review``, Gerrit knows that you want to add another patch set to your existing
change.

The preferred method of working with Git is to create a new branch when working
on a new feature. This way we are able to keep our work separate from the
master branch and to rebase to master when necessary (such as when someone else
adds other features). For example, before starting work on a new feature in
OpenRPD, you could execute ``git checkout -b new-feature-name`` and make all
your commits locally to that branch. Then do a ``git review`` when you're ready
for others to take a look at your work.

If you find you've pushed a change to an existing patch to Gerrit without an
attached "Change-Id", Gerrit can't track the changes together and continues to
create the duplicate changes. You'll need to do the following to get back on
track,

1. In your local openrpd repo, do a ``git review -d yy`` (yy = the change ID of
   the initial patch). This downloads change #yy to a new local branch.
2. Now notice that your working tree has changed to point to a new branch
3. Make your changes/updates/edits to the files, add them to staging, and do a
   ``git commit --amend`` —remember that the Change-Id line must remain the
   same, so don't remove it or change it.
4. When you are ready to add a new patch set to change #yy, do a ``git
   review``. 
   
   .. NOTE::

      Doing a ``git review -f`` will send your changes to Gerrit and then
      delete the local branch so there is less clutter in your local repo.

Preparing a Local Git Repository For Gerrit & Git-review
--------------------------------------------------------

Step-by-Step Instructions:

1. Clone the repository to your local client
2. Configure git to add gerrit as a remote (**gitreview –s will not work
   without this change**):

   .. code-block:: bash
   
      git remote add gerrit ssh://<username>@gerrit.cablelabs.com:29418/my_project

3. Configure git review to setup the commit hooks (do this before making any
   changes):

   .. code-block:: bash

      git review -s

4. **Use Case #1**: create a file in the repo

   a. Create a new file <filename>.
   b. To stage the file:
   
      .. code-block:: bash
      
         git add <filename>

   c. To commit in your local repo:

      .. code-block:: bash

         git commit

   d. Push to master on the remote – bypasses Gerrit review process (if you
      have those permissions, otherwise Gerrit will return an error message):

      .. code-block:: bash

         git push

5. **Use Case #2**: Create a file, approve in Gerrit

   a. Create a new file <filename>.
   b. To stage the file:

      .. code-block:: bash

         git add <filename>

   c. To commit in your local repo:

      .. code-block:: bash

         git commit

   d. Push to ``refs/publish/master`` on the remote:

      .. code-block:: bash

         git review

   e. On Gerrit:

      1. Look for change to review
      2. Select the "Reply" button to provide code review results
         ("Code-Review" +1 or +2 to approve)

         a. Enter comments on the entire patch, individual files, individual
            lines of particular files, or selections of files as needed.
     
      3. “Submit” button to merge change into master

6. **Use Case #3**: Submit and then revise a patch, approve in Gerrit.

   a. Create a new file <filename>.
   b. To stage the file:

      .. code-block:: bash

         git add <filename>

   c. To commit in your local repo:

      .. code-block:: bash

         git commit

   d. Push to ``refs/publish/master`` on the remote and assign Change ID:

      .. code-block:: bash

         git review

   e. "Retrieve" the change to make revisions. Create a temp branch with the
      change in it; puts you in the branch:

      .. code-block:: bash

         git review -d <yy>

   f. Edit your changes into the file & save:

      .. code-block:: bash

         vi <filename>

   g. To stage the new file changes:

      .. code-block:: bash

         git add <filename>

   h. To commit in the temp branch in your local repo; persists the original
      change ID:

      .. code-block:: bash

         git commit --amend

   i. To push the changes you just made to gerrit as a Patch revision (#2)
   ``-f`` deletes the temporary branch:

      .. code-block:: bash

         git review -f

   j. On Gerrit:

      1. Look for change to review – note that there are 2 patch revisions now
         (original plus one more)
      2. Select the "Reply" button to provide code review results
         ("Code-Review" +1 or +2 to approve)

         a. Enter comments on the entire patch, individual files, individual
            lines of particular files, or selections of files as needed.

      3. "Submit" button to merge change into master


