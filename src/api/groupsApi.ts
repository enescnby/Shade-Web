import { API_URL } from "../env";

export interface GroupMemberDto {
  user_id: string;
  shade_id: string;
  role: "owner" | "member";
}

export interface GroupResponseDto {
  group_id: string;
  name: string;
  owner_id: string;
  avatar_url: string;
  members: GroupMemberDto[];
  created_at: string;
}

export async function fetchGroups(accessToken: string): Promise<GroupResponseDto[]> {
  const res = await fetch(`${API_URL}/api/v1/groups`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`groups list: ${res.status}`);
  return res.json();
}

export async function fetchGroup(accessToken: string, groupId: string): Promise<GroupResponseDto> {
  const res = await fetch(`${API_URL}/api/v1/groups/${encodeURIComponent(groupId)}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`groups get: ${res.status}`);
  return res.json();
}

export async function createGroup(
  accessToken: string,
  body: { name: string; member_ids?: string[] },
): Promise<GroupResponseDto> {
  const res = await fetch(`${API_URL}/api/v1/groups`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`groups create: ${res.status}`);
  return res.json();
}
