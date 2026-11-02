# Handling private security issues

When you determine that a security issue will require a private patch, add the "[Blocker]" label to the relevant issue.

When a patch for a private securiy issue is approved by a reviewer:

* Add the "[Security Patch Approved]" and "[Blocker]" labels to the relevant issue.
* Find a issue titled "Private security patch tracking", or create one and tag it with the "[Blocker]" and "[Security]" labels
  * Add a link to the MR(s) related to the issue on your private repo
  * Be sure to do this by editing the description of the issue.
  * Add a parenthetical in the list stating whether the MR completely closes the issue, or whether the issue should be left open.

[Blocker]: https://gitlab.torproject.org/tpo/core/arti/-/work_items?label_name%5B%5D=Blocker
[Security Patch Approved]: https://gitlab.torproject.org/tpo/core/arti/-/work_items?label_name%5B%5D=Security+Patch+Approved
[Security]: https://gitlab.torproject.org/tpo/core/arti/-/work_items?label_name%5B%5D=Security
