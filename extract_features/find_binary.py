import subprocess as sp

def find_binaries(path):
  """
  Gets a list of possible binaries within a firmware sample.

  [Param]
  path : firmware image path
  
  [Return]
  list : a list of binaries
  """

  cmd = f"find '{path}' -executable -type f -exec file {{}} \; | " \
          f"grep -iv image | grep -iv text | awk -F':' '{{print $1}}'"
  p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE, shell=True)
  o, e = p.communicate()
  if o:
    # changed to o.decode() for python3
    return o.decode().split('\n'

  # Null
  return []
